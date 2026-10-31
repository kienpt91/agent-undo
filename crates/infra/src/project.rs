//! Composition root: wires the filesystem adapters of one project's store.

use crate::fs_blobs::FsBlobs;
use crate::fs_journal::FsJournal;
use crate::fs_snapshots::FsSnapshots;
use crate::fs_tree::FsTree;
use crate::layout::StoreDir;
use crate::lock::FsLocker;
use crate::process::ProcessRunner;
use crate::support::SystemClock;
use agent_undo_app::ports::{EventSink, Ports};

pub struct Project {
    pub store: StoreDir,
    clock: SystemClock,
    sink: Box<dyn EventSink>,
    locker: FsLocker,
    journal: FsJournal,
    snapshots: FsSnapshots,
    blobs: FsBlobs,
    tree: FsTree,
    runner: ProcessRunner,
}

impl Project {
    pub fn new(store: StoreDir, sink: Box<dyn EventSink>) -> Project {
        let blobs = FsBlobs::new(store.blobs_dir(), store.tmp_dir());
        Project {
            clock: SystemClock,
            sink,
            locker: FsLocker::new(store.lock_path()),
            journal: FsJournal::new(store.log_path(), store.pruned_path()),
            snapshots: FsSnapshots::new(store.checkpoints_dir(), store.tmp_dir()),
            tree: FsTree::new(
                store.root.clone(),
                &store.dir,
                store.meta.max_file_size,
                *store.key(),
                blobs.clone(),
            ),
            blobs,
            runner: ProcessRunner::new(store.root.clone()),
            store,
        }
    }

    /// The ports bundle handed to use cases.
    pub fn ports(&self) -> Ports<'_> {
        Ports {
            clock: &self.clock,
            events: self.sink.as_ref(),
            locks: &self.locker,
            journal: &self.journal,
            snapshots: &self.snapshots,
            blobs: &self.blobs,
            tree: &self.tree,
            runner: &self.runner,
        }
    }
}
