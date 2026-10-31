//! One tick of `watch`: scan, feed the debouncer, record when the quiet period passed.

use super::record::{CheckpointRequest, record_checkpoint};
use super::status::scan_pending;
use crate::error::{Error, Result};
use crate::events::Event;
use crate::ports::Ports;
use agent_undo_domain::journal::{CheckpointRecord, CkptKind, Label};
use agent_undo_domain::watch::{Debouncer, Tick};

#[derive(Debug, Clone)]
pub struct WatchStep {
    pub tick: Tick,
    pub committed: Option<CheckpointRecord>,
    /// The store was busy (another operation holds the lock); nothing was scanned.
    pub skipped_busy: bool,
}

pub fn watch_tick(
    ports: &Ports<'_>,
    debouncer: &mut Debouncer,
    label: Option<&Label>,
) -> Result<WatchStep> {
    let _guard = match ports.locks.exclusive() {
        Ok(g) => g,
        Err(Error::Locked(_)) => {
            return Ok(WatchStep {
                tick: Tick::Idle,
                committed: None,
                skipped_busy: true,
            });
        }
        Err(e) => return Err(e),
    };
    let mut journal = ports.journal.load()?;
    let pending = scan_pending(ports, &journal)?;
    let fp = (pending.counts.total() > 0).then_some(pending.fingerprint);
    let tick = debouncer.observe(ports.clock.now_ns(), fp);
    let mut committed = None;
    if tick == Tick::Commit {
        let mut req = CheckpointRequest::new(CkptKind::Watch);
        req.label = label.cloned();
        req.skip_if_empty = true;
        committed = record_checkpoint(ports, &mut journal, req)?.record;
        if let Some(r) = &committed {
            ports.events.publish(Event::WatchCommitted {
                checkpoint: r.id,
                changes: r.counts,
            });
        }
    }
    Ok(WatchStep {
        tick,
        committed,
        skipped_busy: false,
    })
}
