//! `verify`: re-check the hash chain, every checkpoint file and every blob.

use crate::error::{Error, Result};
use crate::ports::Ports;
use agent_undo_domain::entry::Kind;
use agent_undo_domain::hash::{Digest, to_hex};
use std::collections::HashSet;

#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub checkpoints_checked: u64,
    pub checkpoints_pruned: u64,
    pub blobs_checked: u64,
    pub blobs_unreferenced: u64,
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

pub fn verify(ports: &Ports<'_>) -> Result<VerifyReport> {
    let _guard = ports.locks.shared()?;
    let mut report = VerifyReport::default();
    let journal = match ports.journal.load() {
        Ok(j) => j,
        Err(Error::Integrity(m) | Error::Format(m)) => {
            report.problems.push(format!("journal: {m}"));
            return Ok(report);
        }
        Err(e) => return Err(e),
    };
    let mut referenced: HashSet<Digest> = HashSet::new();
    for rec in journal.records() {
        if journal.is_pruned(rec.id) {
            report.checkpoints_pruned += 1;
            continue;
        }
        report.checkpoints_checked += 1;
        match ports.snapshots.stored_digests(rec.id) {
            Ok(d) => {
                if d.manifest != rec.manifest {
                    report.problems.push(format!(
                        "checkpoint {}: manifest does not match the journal (modified or corrupt)",
                        rec.id
                    ));
                }
                if d.changes != rec.changes {
                    report.problems.push(format!("checkpoint {}: change set does not match the journal (modified or corrupt)", rec.id));
                }
            }
            Err(e) => {
                report.problems.push(format!("checkpoint {}: {e}", rec.id));
                continue;
            }
        }
        match ports.snapshots.open_manifest(rec.id) {
            Ok(mut m) => {
                let mut n = 0u64;
                loop {
                    match m.next_entry() {
                        Ok(Some((_, e))) => {
                            n += 1;
                            if let Some(d) = e.blob() {
                                referenced.insert(d);
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            report
                                .problems
                                .push(format!("checkpoint {} manifest: {e}", rec.id));
                            break;
                        }
                    }
                }
                if n != rec.entries && report.problems.is_empty() {
                    report.problems.push(format!(
                        "checkpoint {}: manifest has {n} entries, the journal says {}",
                        rec.id, rec.entries
                    ));
                }
            }
            Err(e) => report
                .problems
                .push(format!("checkpoint {} manifest: {e}", rec.id)),
        }
        match ports.snapshots.open_changes(rec.id) {
            Ok(mut c) => loop {
                match c.next_change() {
                    Ok(Some(ch)) => {
                        for side in [ch.before(), ch.after()].into_iter().flatten() {
                            if side.kind() == Kind::File
                                && let Some(d) = side.digest()
                            {
                                referenced.insert(d);
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        report
                            .problems
                            .push(format!("checkpoint {} changes: {e}", rec.id));
                        break;
                    }
                }
            },
            Err(e) => report
                .problems
                .push(format!("checkpoint {} changes: {e}", rec.id)),
        }
    }
    let listing = ports.blobs.list()?;
    let present: HashSet<Digest> = listing.blobs.iter().map(|(d, _)| *d).collect();
    for (d, _) in &listing.blobs {
        report.blobs_checked += 1;
        match ports.blobs.hash_stored(d) {
            Ok(actual) if actual == *d => {}
            Ok(_) => report.problems.push(format!(
                "blob {} is corrupt (content does not match its hash)",
                to_hex(d)
            )),
            Err(e) => report.problems.push(format!("blob {}: {e}", to_hex(d))),
        }
        if !referenced.contains(d) {
            report.blobs_unreferenced += 1;
        }
    }
    let mut missing: Vec<&Digest> = referenced
        .iter()
        .filter(|d| !present.contains(*d))
        .collect();
    missing.sort();
    for d in missing {
        report.problems.push(format!(
            "blob {} is referenced but missing from the store",
            to_hex(d)
        ));
    }
    for s in &listing.strays {
        report
            .warnings
            .push(format!("unexpected entry in the blob area: {s}"));
    }
    let known: HashSet<u64> = journal.records().iter().map(|r| r.id.get()).collect();
    for id in ports.snapshots.list()? {
        if !known.contains(&id.get()) {
            report.warnings.push(format!(
                "orphan files for checkpoint {id} (not in the journal; harmless)"
            ));
        }
    }
    Ok(report)
}
