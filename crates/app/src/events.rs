//! Events published by use cases (domain events plus application-level events).

use agent_undo_domain::change::Counts;
use agent_undo_domain::journal::{CheckpointId, CkptKind, DomainEvent, ExitInfo};
use agent_undo_domain::path::RelPath;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Raised by the journal aggregate.
    Domain(DomainEvent),
    /// A file was recorded as sensitive: its content was not stored.
    SensitiveContentWithheld { path: RelPath },
    /// The wrapped command of a `run` finished.
    CommandFinished { exit: ExitInfo },
    /// An undo or restore changed the project.
    ReversalApplied {
        kind: CkptKind,
        checkpoint: CheckpointId,
        applied: u64,
        skipped: u64,
    },
    /// An undo or restore was refused; nothing was changed.
    ReversalRefused { reason: String },
    /// `gc` removed checkpoints and unreferenced blobs.
    GarbageCollected { checkpoints: u64, blobs: u64 },
    /// `watch` recorded a checkpoint after a quiet period.
    WatchCommitted {
        checkpoint: CheckpointId,
        changes: Counts,
    },
}
