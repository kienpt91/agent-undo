//! `flock`-based store lock.

use agent_undo_app::error::{Ctx, Error, Result};
use agent_undo_app::ports::{LockGuard, Locker};
use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub struct FsLocker {
    path: PathBuf,
}

struct Guard {
    _file: File,
}

impl LockGuard for Guard {}

impl FsLocker {
    pub fn new(path: PathBuf) -> FsLocker {
        FsLocker { path }
    }

    fn acquire(&self, exclusive: bool) -> Result<Box<dyn LockGuard>> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&self.path)
            .ctx(|| "opening lock file".into())?;
        let r = if exclusive {
            f.try_lock()
        } else {
            f.try_lock_shared()
        };
        match r {
            Ok(()) => Ok(Box::new(Guard { _file: f })),
            Err(TryLockError::WouldBlock) => Err(Error::Locked(
                "another agent-undo operation is using this store (lock held)".into(),
            )),
            Err(TryLockError::Error(e)) => Err(Error::io("locking store", e)),
        }
    }
}

impl Locker for FsLocker {
    fn exclusive(&self) -> Result<Box<dyn LockGuard>> {
        self.acquire(true)
    }

    fn shared(&self) -> Result<Box<dyn LockGuard>> {
        self.acquire(false)
    }
}
