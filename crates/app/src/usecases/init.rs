//! Initialization: record the baseline checkpoint of a fresh store.

use super::record::{CheckpointRequest, record_checkpoint};
use crate::error::{Error, Result};
use crate::ports::{Ports, ScanStats};
use agent_undo_domain::journal::{CheckpointRecord, CkptKind, Label};

pub struct Baseline {
    pub record: CheckpointRecord,
    pub stats: ScanStats,
}

/// Records checkpoint #1. Fails with `AlreadyInitialized` if the journal is not empty.
pub fn record_baseline(ports: &Ports<'_>) -> Result<Baseline> {
    let _guard = ports.locks.exclusive()?;
    let mut journal = ports.journal.load()?;
    if !journal.is_empty() {
        return Err(Error::AlreadyInitialized(
            "this project already has a baseline checkpoint".into(),
        ));
    }
    let mut req = CheckpointRequest::new(CkptKind::Baseline);
    req.label = Some(Label::new(b"baseline".to_vec())?);
    let out = record_checkpoint(ports, &mut journal, req)?;
    let record = out
        .record
        .ok_or_else(|| Error::Other("internal error: baseline was not recorded".into()))?;
    Ok(Baseline {
        record,
        stats: out.stats,
    })
}
