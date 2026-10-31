//! Status and pending-change scanning (shared by `status` and `watch`).

use crate::error::{Error, Result};
use crate::ports::{ManifestStream, Ports, ScanOptions, ScanStats, ScanVisitor};
use agent_undo_domain::change::{Change, Counts, Merger, fingerprint_step};
use agent_undo_domain::entry::Entry;
use agent_undo_domain::journal::{CheckpointRecord, Journal, SessionId};
use agent_undo_domain::path::RelPath;

/// How many individual pending changes are kept for display.
pub const SCAN_SAMPLE: usize = 1000;

#[derive(Debug, Clone, Default)]
pub struct Pending {
    pub counts: Counts,
    pub sample: Vec<Change>,
    pub stats: ScanStats,
    /// Order-independent fingerprint of the pending change set.
    pub fingerprint: u64,
}

struct PendingVisitor {
    merger: Merger<ManifestStream>,
    pending: Pending,
}

impl PendingVisitor {
    fn note(p: &mut Pending, c: Change) -> Result<()> {
        p.counts.add(c.kind());
        p.fingerprint = fingerprint_step(p.fingerprint, &c);
        if p.sample.len() < SCAN_SAMPLE {
            p.sample.push(c);
        }
        Ok(())
    }
}

impl ScanVisitor for PendingVisitor {
    fn prev(&mut self, path: &RelPath) -> Result<Option<Entry>> {
        let PendingVisitor { merger, pending } = self;
        merger.lookup(path, &mut |c| PendingVisitor::note(pending, c))
    }

    fn visit(&mut self, path: &RelPath, entry: &Entry) -> Result<()> {
        let PendingVisitor { merger, pending } = self;
        merger.push(path, entry, &mut |c| PendingVisitor::note(pending, c))
    }

    fn carry_forward(&mut self, dir: &RelPath) -> Result<()> {
        while let Some((p, e)) = self.merger.next_under(dir)? {
            self.visit(&p, &e)?;
        }
        Ok(())
    }
}

/// Compares the working tree with the newest checkpoint without writing anything.
/// The caller holds a lock.
pub fn scan_pending(ports: &Ports<'_>, journal: &Journal) -> Result<Pending> {
    let head = journal.head().ok_or_else(|| {
        Error::NotInitialized("the journal has no baseline; run `agent-undo init`".into())
    })?;
    let mut v = PendingVisitor {
        merger: Merger::new(Some(ports.snapshots.open_manifest(head.id)?)),
        pending: Pending::default(),
    };
    let stats = ports
        .tree
        .scan(&ScanOptions::observing(Some(head.time_ns)), &mut v)?;
    {
        let PendingVisitor { merger, pending } = &mut v;
        merger.finish(&mut |c| PendingVisitor::note(pending, c))?;
    }
    v.pending.stats = stats;
    Ok(v.pending)
}

#[derive(Debug, Clone)]
pub struct StatusReport {
    pub checkpoints: u64,
    pub head: Option<CheckpointRecord>,
    pub session: Option<SessionId>,
    pub pruned: u64,
    /// `None` when another operation holds the lock and the scan was skipped.
    pub pending: Option<Pending>,
    pub locked_by_other: bool,
}

pub fn status(ports: &Ports<'_>) -> Result<StatusReport> {
    let guard = match ports.locks.shared() {
        Ok(g) => Some(g),
        Err(Error::Locked(_)) => None,
        Err(e) => return Err(e),
    };
    let Some(_guard) = guard else {
        return Ok(StatusReport {
            checkpoints: 0,
            head: None,
            session: None,
            pending: None,
            pruned: 0,
            locked_by_other: true,
        });
    };
    let journal = ports.journal.load()?;
    let pending = if journal.is_empty() {
        None
    } else {
        Some(scan_pending(ports, &journal)?)
    };
    Ok(StatusReport {
        checkpoints: journal.records().len() as u64,
        head: journal.head().cloned(),
        session: journal.current_session(),
        pruned: journal.pruned().len() as u64,
        pending,
        locked_by_other: false,
    })
}
