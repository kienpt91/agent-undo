//! Manual checkpoint and listing the log.

use super::record::{CheckpointRequest, record_checkpoint};
use crate::error::{Error, Result};
use crate::ports::{Ports, ScanStats};
use agent_undo_domain::journal::{CheckpointRecord, CkptKind, Journal, Label};

pub struct ManualCheckpoint {
    pub record: CheckpointRecord,
    pub stats: ScanStats,
}

/// Records a manual checkpoint of the current state.
pub fn manual_checkpoint(
    ports: &Ports<'_>,
    label: Option<Label>,
    new_session: bool,
) -> Result<ManualCheckpoint> {
    let _guard = ports.locks.exclusive()?;
    let mut journal = ports.journal.load()?;
    if journal.is_empty() {
        return Err(Error::NotInitialized(
            "the journal has no baseline; run `agent-undo init`".into(),
        ));
    }
    let mut req = CheckpointRequest::new(CkptKind::Manual);
    req.label = label;
    req.new_session = new_session;
    let out = record_checkpoint(ports, &mut journal, req)?;
    let record = out
        .record
        .ok_or_else(|| Error::Other("internal error: checkpoint was not recorded".into()))?;
    Ok(ManualCheckpoint {
        record,
        stats: out.stats,
    })
}

/// Loads the journal for listing (read-only).
pub fn load_log(ports: &Ports<'_>) -> Result<Journal> {
    let _guard = ports.locks.shared()?;
    ports.journal.load()
}
