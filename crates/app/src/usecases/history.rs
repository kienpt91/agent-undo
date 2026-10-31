//! `diff`: the changes of one checkpoint with text diffs of small text files.

use crate::error::{Error, Result};
use crate::ports::Ports;
use agent_undo_domain::change::{Change, Rename, detect_renames};
use agent_undo_domain::diff::{DiffOutcome, MAX_DIFF_BYTES, unified};
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::journal::{CheckpointId, CheckpointRecord};

/// Most changes listed in one diff.
pub const MAX_DIFF_CHANGES: usize = 50_000;
/// Most text diffs produced in one report; the rest are path-level only.
pub const MAX_TEXT_DIFFS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// A text diff (or reason it is omitted).
    Diff(DiffOutcome),
    /// No content is shown for this change, for the stated reason.
    Withheld(&'static str),
}

#[derive(Debug, Clone)]
pub struct ChangeView {
    pub change: Change,
    pub content: Content,
}

#[derive(Debug, Clone)]
pub struct DiffReport {
    pub record: CheckpointRecord,
    pub changes: Vec<ChangeView>,
    pub renames: Vec<Rename>,
    pub truncated: bool,
}

fn withheld_reason(e: &Option<Entry>) -> Option<&'static str> {
    match e.as_ref().map(Entry::kind) {
        Some(Kind::Sensitive) => Some("sensitive file: content is never stored or shown"),
        Some(Kind::TooLarge) => Some("too-large file: content was not recorded"),
        Some(Kind::Special | Kind::Unreadable) => Some("content was not recorded"),
        _ => None,
    }
}

fn load_side(ports: &Ports<'_>, e: Option<&Entry>) -> Result<Option<Vec<u8>>> {
    match e {
        None => Ok(Some(Vec::new())),
        Some(e) => match e.blob() {
            Some(d) if e.size() as usize <= MAX_DIFF_BYTES => {
                Ok(Some(ports.blobs.read(&d, MAX_DIFF_BYTES as u64)?))
            }
            _ => Ok(None),
        },
    }
}

pub fn diff_checkpoint(ports: &Ports<'_>, id: CheckpointId) -> Result<DiffReport> {
    let _guard = ports.locks.shared()?;
    let journal = ports.journal.load()?;
    let record = journal.find(id)?.clone();
    if journal.is_pruned(id) {
        return Err(Error::Refused(format!(
            "checkpoint {id} was removed by gc; its data is gone"
        )));
    }
    let mut stream = ports.snapshots.open_changes(id)?;
    let mut changes: Vec<Change> = Vec::new();
    let mut truncated = false;
    while let Some(c) = stream.next_change()? {
        if changes.len() >= MAX_DIFF_CHANGES {
            truncated = true;
            break;
        }
        changes.push(c);
    }
    let renames = detect_renames(&changes);
    let mut views = Vec::with_capacity(changes.len());
    let mut diffs = 0usize;
    for change in changes {
        let before = change.before().cloned();
        let after = change.after().cloned();
        let content = if let Some(r) = withheld_reason(&before).or_else(|| withheld_reason(&after))
        {
            Content::Withheld(r)
        } else if [&before, &after]
            .iter()
            .any(|e| e.as_ref().is_some_and(|e| !matches!(e.kind(), Kind::File)))
        {
            Content::Withheld(
                match (
                    before.as_ref().map(Entry::kind),
                    after.as_ref().map(Entry::kind),
                ) {
                    (Some(Kind::Dir), _) | (_, Some(Kind::Dir)) => "directory",
                    (Some(Kind::Symlink), _) | (_, Some(Kind::Symlink)) => "symlink",
                    _ => "not a regular file",
                },
            )
        } else if diffs >= MAX_TEXT_DIFFS {
            Content::Diff(DiffOutcome::Omitted(
                "diff limit reached; showing paths only",
            ))
        } else {
            match (
                load_side(ports, before.as_ref())?,
                load_side(ports, after.as_ref())?,
            ) {
                (Some(old), Some(new)) => {
                    diffs += 1;
                    Content::Diff(unified(&old, &new))
                }
                _ => Content::Diff(DiffOutcome::Omitted("file too large for a text diff")),
            }
        };
        views.push(ChangeView { change, content });
    }
    Ok(DiffReport {
        record,
        changes: views,
        renames,
        truncated,
    })
}
