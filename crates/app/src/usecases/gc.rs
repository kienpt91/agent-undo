//! `gc`: prune old checkpoints and delete blobs nothing references anymore.

use crate::error::Result;
use crate::events::Event;
use crate::ports::Ports;
use agent_undo_domain::entry::Kind;
use agent_undo_domain::hash::Digest;
use agent_undo_domain::journal::{CheckpointId, DomainEvent, RetentionPolicy};
use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct GcReport {
    pub applied: bool,
    pub checkpoints: Vec<CheckpointId>,
    pub blobs: u64,
    pub blob_bytes: u64,
    pub retained: u64,
}

/// Plans (and with `apply`, performs) garbage collection under `policy`.
pub fn gc(ports: &Ports<'_>, policy: RetentionPolicy, apply: bool) -> Result<GcReport> {
    let _guard = ports.locks.exclusive()?;
    let mut journal = ports.journal.load()?;
    let now = ports.clock.now_ns();
    let doomed = journal.prunable(policy, now);
    let doomed_set: HashSet<u64> = doomed.iter().map(|i| i.get()).collect();
    // Blobs still referenced by the checkpoints that stay.
    let mut referenced: HashSet<Digest> = HashSet::new();
    let mut retained = 0u64;
    for rec in journal.records() {
        if journal.is_pruned(rec.id) || doomed_set.contains(&rec.id.get()) {
            continue;
        }
        retained += 1;
        let mut m = ports.snapshots.open_manifest(rec.id)?;
        while let Some((_, e)) = m.next_entry()? {
            if let Some(d) = e.blob() {
                referenced.insert(d);
            }
        }
        let mut c = ports.snapshots.open_changes(rec.id)?;
        while let Some(ch) = c.next_change()? {
            for side in [ch.before(), ch.after()].into_iter().flatten() {
                if side.kind() == Kind::File
                    && let Some(d) = side.digest()
                {
                    referenced.insert(d);
                }
            }
        }
    }
    let listing = ports.blobs.list()?;
    let garbage: Vec<(Digest, u64)> = listing
        .blobs
        .into_iter()
        .filter(|(d, _)| !referenced.contains(d))
        .collect();
    let report = GcReport {
        applied: apply,
        checkpoints: doomed.clone(),
        blobs: garbage.len() as u64,
        blob_bytes: garbage.iter().map(|(_, s)| *s).sum(),
        retained,
    };
    if !apply {
        return Ok(report);
    }
    let events = journal.prune(&doomed)?;
    ports.journal.save_pruned(&doomed)?;
    for id in &doomed {
        ports.snapshots.remove(*id)?;
    }
    for (d, _) in &garbage {
        ports.blobs.remove(d)?;
    }
    for e in events {
        if matches!(e, DomainEvent::CheckpointsPruned { .. }) {
            ports.events.publish(Event::Domain(e));
        }
    }
    if !doomed.is_empty() || !garbage.is_empty() {
        ports.events.publish(Event::GarbageCollected {
            checkpoints: doomed.len() as u64,
            blobs: garbage.len() as u64,
        });
    }
    Ok(report)
}
