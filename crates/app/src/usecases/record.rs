//! Recording a checkpoint: scan the project, merge against the previous
//! manifest, persist manifest and change set, seal the record in the journal.

use crate::error::Result;
use crate::events::Event;
use crate::ports::{CheckpointWriter, ManifestStream, Ports, ScanOptions, ScanStats, ScanVisitor};
use agent_undo_domain::change::{Change, Counts, Merger};
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::journal::{
    CheckpointId, CheckpointRecord, CkptKind, CommandLine, ExitInfo, Journal, Label, NewCheckpoint,
};
use agent_undo_domain::path::RelPath;

#[derive(Debug, Clone)]
pub struct CheckpointRequest {
    pub kind: CkptKind,
    pub label: Option<Label>,
    pub command: Option<CommandLine>,
    pub exit: Option<ExitInfo>,
    pub new_session: bool,
    pub reference: Option<CheckpointId>,
    /// Record nothing (and return `None`) if the tree equals the previous checkpoint.
    pub skip_if_empty: bool,
}

impl CheckpointRequest {
    pub fn new(kind: CkptKind) -> CheckpointRequest {
        CheckpointRequest {
            kind,
            label: None,
            command: None,
            exit: None,
            new_session: false,
            reference: None,
            skip_if_empty: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Recorded {
    pub record: Option<CheckpointRecord>,
    pub stats: ScanStats,
}

struct Recorder {
    merger: Merger<ManifestStream>,
    writer: Box<dyn CheckpointWriter>,
    counts: Counts,
    withheld: Vec<RelPath>,
}

impl Recorder {
    fn emit(
        writer: &mut dyn CheckpointWriter,
        counts: &mut Counts,
        withheld: &mut Vec<RelPath>,
        c: Change,
    ) -> Result<()> {
        counts.add(c.kind());
        if c.after().is_some_and(|a| a.kind() == Kind::Sensitive) {
            withheld.push(c.path().clone());
        }
        writer.write_change(&c)
    }
}

impl ScanVisitor for Recorder {
    fn prev(&mut self, path: &RelPath) -> Result<Option<Entry>> {
        let Recorder {
            merger,
            writer,
            counts,
            withheld,
        } = self;
        merger.lookup(path, &mut |c| {
            Recorder::emit(writer.as_mut(), counts, withheld, c)
        })
    }

    fn visit(&mut self, path: &RelPath, entry: &Entry) -> Result<()> {
        self.writer.write_entry(path, entry)?;
        let Recorder {
            merger,
            writer,
            counts,
            withheld,
        } = self;
        merger.push(path, entry, &mut |c| {
            Recorder::emit(writer.as_mut(), counts, withheld, c)
        })
    }

    fn carry_forward(&mut self, dir: Option<&RelPath>) -> Result<()> {
        // The previous entries stay as they were: record them unchanged, report no change.
        loop {
            let next = match dir {
                Some(d) => self.merger.next_under(d)?,
                None => self.merger.next_remaining()?,
            };
            let Some((p, e)) = next else { return Ok(()) };
            self.writer.write_entry(&p, &e)?;
        }
    }
}

/// Records the next checkpoint. The caller holds the exclusive lock.
pub fn record_checkpoint(
    ports: &Ports<'_>,
    journal: &mut Journal,
    req: CheckpointRequest,
) -> Result<Recorded> {
    let started = ports.clock.now_ns();
    let id = journal.next_id();
    let prev = journal.head().cloned();
    let prev_stream = match &prev {
        Some(p) => Some(ports.snapshots.open_manifest(p.id)?),
        None => None,
    };
    let mut rec = Recorder {
        merger: Merger::new(prev_stream),
        writer: ports.snapshots.begin(id)?,
        counts: Counts::default(),
        withheld: Vec::new(),
    };
    let opts = ScanOptions::capturing(prev.as_ref().map(|p| p.time_ns));
    let stats = ports.tree.scan(&opts, &mut rec)?;
    {
        let Recorder {
            merger,
            writer,
            counts,
            withheld,
        } = &mut rec;
        merger.finish(&mut |c| Recorder::emit(writer.as_mut(), counts, withheld, c))?;
    }
    if req.skip_if_empty && rec.counts.total() == 0 {
        return Ok(Recorded {
            record: None,
            stats,
        });
    }
    let counts = rec.counts;
    let withheld = std::mem::take(&mut rec.withheld);
    let written = rec.writer.commit()?;
    let mut new = NewCheckpoint::new(
        req.kind,
        started,
        written.manifest,
        written.changes,
        counts,
        written.entries,
    );
    new.label = req.label;
    new.command = req.command;
    new.exit = req.exit;
    new.new_session = req.new_session;
    new.reference = req.reference;
    let (record, events) = journal.record(new)?;
    ports.journal.append(&record)?;
    for path in withheld {
        ports
            .events
            .publish(Event::SensitiveContentWithheld { path });
    }
    for e in events {
        ports.events.publish(Event::Domain(e));
    }
    Ok(Recorded {
        record: Some(record),
        stats,
    })
}
