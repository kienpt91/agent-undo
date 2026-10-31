//! Undo and restore: build a plan from recorded history, refuse on conflicts,
//! save the current state as a `pre-undo` checkpoint, apply with per-path
//! re-validation, and record the result as a checkpoint of its own (so an undo
//! is itself undoable).

use super::record::{CheckpointRequest, record_checkpoint};
use crate::error::{Error, Result};
use crate::events::Event;
use crate::ports::Ports;
use agent_undo_domain::change::NetChanges;
use agent_undo_domain::entry::Entry;
use agent_undo_domain::journal::{
    CheckpointId, CheckpointRecord, CkptKind, Journal, Label, MAX_LABEL_BYTES, Selector,
};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{
    Observation, Outcome, Plan, PlanItem, build_item, execution_order, resolve_obstructions,
    restore_inputs, same_state, sort_dir_modes, undo_inputs,
};

/// Upper bound on the number of paths one plan may hold in memory.
pub const MAX_PLAN_ENTRIES: usize = 250_000;

type Inputs = Vec<(RelPath, Option<Entry>, Option<Option<Entry>>)>;

fn items_from(ports: &Ports<'_>, inputs: Inputs) -> Result<Vec<PlanItem>> {
    let mut inputs = inputs;
    inputs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut items = Vec::with_capacity(inputs.len());
    for (path, target, expected) in inputs {
        let observed = ports.tree.observe(&path)?;
        items.push(build_item(path, target, expected, observed));
    }
    resolve_obstructions(&mut items);
    Ok(items)
}

fn plan_undo_in(ports: &Ports<'_>, journal: &Journal, sel: &Selector) -> Result<Plan> {
    let ids = journal.select(sel)?;
    let mut net = NetChanges::new(MAX_PLAN_ENTRIES);
    for id in &ids {
        let mut changes = ports.snapshots.open_changes(*id)?;
        while let Some(c) = changes.next_change()? {
            net.add(c)?;
        }
    }
    let description = match sel {
        Selector::Session(_) => format!(
            "undo session ({} checkpoints: {}..{})",
            ids.len(),
            ids.first().map_or(0, |i| i.get()),
            ids.last().map_or(0, |i| i.get())
        ),
        _ => format!(
            "undo checkpoint {}",
            ids.first().map_or_else(String::new, ToString::to_string)
        ),
    };
    Ok(Plan {
        kind: CkptKind::Undo,
        description,
        sources: ids,
        items: items_from(ports, undo_inputs(net.into_net()))?,
    })
}

fn plan_restore_in(
    ports: &Ports<'_>,
    journal: &Journal,
    root: &RelPath,
    from: CheckpointId,
) -> Result<Plan> {
    let rec = journal.find(from)?;
    if journal.is_pruned(rec.id) {
        return Err(Error::Refused(format!(
            "checkpoint {from} was removed by gc; its data is gone"
        )));
    }
    let mut stream = ports.snapshots.open_manifest(rec.id)?;
    let mut entries: Vec<(RelPath, Entry)> = Vec::new();
    while let Some((p, e)) = stream.next_entry()? {
        if p.is_within(root) {
            if entries.len() >= MAX_PLAN_ENTRIES {
                return Err(Error::Limit(format!(
                    "more than {MAX_PLAN_ENTRIES} paths below the requested path"
                )));
            }
            entries.push((p, e));
        } else if p > *root {
            break;
        }
    }
    Ok(Plan {
        kind: CkptKind::Restore,
        description: format!("restore {} from checkpoint {}", root.display(), rec.id),
        sources: vec![rec.id],
        items: items_from(ports, restore_inputs(root, entries))?,
    })
}

/// Read-only: what `undo` would do.
pub fn plan_undo(ports: &Ports<'_>, sel: &Selector) -> Result<Plan> {
    let _guard = ports.locks.shared()?;
    let journal = ports.journal.load()?;
    plan_undo_in(ports, &journal, sel)
}

/// Read-only: what `restore` would do.
pub fn plan_restore(ports: &Ports<'_>, root: &RelPath, from: CheckpointId) -> Result<Plan> {
    let _guard = ports.locks.shared()?;
    let journal = ports.journal.load()?;
    plan_restore_in(ports, &journal, root, from)
}

#[derive(Debug, Clone)]
pub struct ReversalReport {
    pub plan: Plan,
    /// Set when nothing was changed because the plan needs `--force`.
    pub refused: Option<String>,
    /// Snapshot of the state before anything was modified.
    pub pre_undo: Option<CheckpointRecord>,
    /// Checkpoint recording what the reversal changed.
    pub result: Option<CheckpointRecord>,
    /// One outcome per plan item (same order as `plan.items`).
    pub outcomes: Vec<Outcome>,
    /// First failure, if the apply stopped early.
    pub error: Option<String>,
}

impl ReversalReport {
    pub fn applied(&self) -> u64 {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Applied))
            .count() as u64
    }

    pub fn skipped(&self) -> u64 {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Skipped(_)))
            .count() as u64
    }
}

fn label_for(text: &str) -> Option<Label> {
    let bytes = text.as_bytes();
    Label::new(
        bytes
            .get(..bytes.len().min(MAX_LABEL_BYTES))
            .unwrap_or(bytes)
            .to_vec(),
    )
    .ok()
}

fn apply_plan(
    ports: &Ports<'_>,
    journal: &mut Journal,
    plan: Plan,
    force: bool,
) -> Result<ReversalReport> {
    let mut report = ReversalReport {
        outcomes: plan.items.iter().map(|_| Outcome::NotAttempted).collect(),
        plan,
        refused: None,
        pre_undo: None,
        result: None,
        error: None,
    };
    if report.plan.has_conflicts() && !force {
        let reason =
            "some paths were modified after the checkpoint; re-run with --force to overwrite them"
                .to_string();
        ports.events.publish(Event::ReversalRefused {
            reason: reason.clone(),
        });
        report.refused = Some(reason);
        return Ok(report);
    }
    if !report.plan.items.iter().any(|i| i.status.runnable(force)) {
        return Ok(report);
    }
    let reference = report.plan.sources.first().copied();
    // Save the current state first: the undo must itself be undoable.
    let mut pre = CheckpointRequest::new(CkptKind::PreUndo);
    pre.reference = reference;
    pre.label = label_for(&format!("before: {}", report.plan.description));
    report.pre_undo = record_checkpoint(ports, journal, pre)?.record;

    let mut dir_modes: Vec<(RelPath, u32)> = Vec::new();
    for idx in execution_order(&report.plan.items) {
        let Some(item) = report.plan.items.get(idx) else {
            continue;
        };
        let outcome = if item.status.runnable(force) {
            match execute_item(ports, item, &mut dir_modes) {
                Ok(o) => o,
                Err(e) => {
                    report.error = Some(format!("{}: {e}", item.path.display()));
                    if let Some(slot) = report.outcomes.get_mut(idx) {
                        *slot = Outcome::Failed(e.to_string());
                    }
                    break;
                }
            }
        } else {
            Outcome::Skipped(
                item.status
                    .reason()
                    .map_or_else(|| item.status.as_str().to_string(), str::to_string),
            )
        };
        if let Some(slot) = report.outcomes.get_mut(idx) {
            *slot = outcome;
        }
    }
    if report.error.is_none() {
        sort_dir_modes(&mut dir_modes);
        for (path, mode) in dir_modes {
            if let Err(e) = ports.tree.set_dir_mode(&path, mode) {
                report.error = Some(format!("{}: {e}", path.display()));
                break;
            }
        }
    }
    // Always record what happened, even after a partial failure.
    let mut post = CheckpointRequest::new(report.plan.kind);
    post.reference = reference;
    post.label = label_for(&report.plan.description);
    let rec = record_checkpoint(ports, journal, post)?.record;
    if let Some(r) = &rec {
        ports.events.publish(Event::ReversalApplied {
            kind: r.kind,
            checkpoint: r.id,
            applied: report.applied(),
            skipped: report.skipped(),
        });
    }
    report.result = rec;
    Ok(report)
}

/// Re-validates the path right before touching it, then executes the item.
fn execute_item(
    ports: &Ports<'_>,
    item: &PlanItem,
    dir_modes: &mut Vec<(RelPath, u32)>,
) -> Result<Outcome> {
    match ports.tree.observe(&item.path)? {
        Observation::State(now) if same_state(&now, &item.current) => {}
        Observation::State(_) => {
            return Err(Error::Unsafe(format!(
                "{} changed after the plan was made; nothing was modified for it",
                item.path.display()
            )));
        }
        Observation::Unsafe(why) | Observation::Obstructed(why) => return Err(Error::Unsafe(why)),
    }
    ports.tree.apply(item, dir_modes)
}

/// Undoes the selected checkpoints (exclusive lock, pre-undo checkpoint, result checkpoint).
pub fn apply_undo(ports: &Ports<'_>, sel: &Selector, force: bool) -> Result<ReversalReport> {
    let _guard = ports.locks.exclusive()?;
    let mut journal = ports.journal.load()?;
    let plan = plan_undo_in(ports, &journal, sel)?;
    apply_plan(ports, &mut journal, plan, force)
}

/// Restores `root` to its state in checkpoint `from`.
pub fn apply_restore(
    ports: &Ports<'_>,
    root: &RelPath,
    from: CheckpointId,
    force: bool,
) -> Result<ReversalReport> {
    let _guard = ports.locks.exclusive()?;
    let mut journal = ports.journal.load()?;
    let plan = plan_restore_in(ports, &journal, root, from)?;
    apply_plan(ports, &mut journal, plan, force)
}
