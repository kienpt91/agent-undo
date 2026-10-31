//! Persistence of the sensitive-content registry (`sensitive-ids` in the store).
//!
//! The registry holds the keyed ids (`policy::sensitive_id`) of every content that
//! was ever classified as sensitive, one hex line each. It is what makes a copy
//! or rename of a secret file stay sensitive: classification compares the keyed id
//! of the content being read against it, whatever the file is called now. It
//! stores no content and no plain hash, only HMAC values under the store key.

use crate::fsutil::{O_NOFOLLOW, display_path};
use crate::layout::read_small;
use agent_undo_app::error::{Ctx, Error, Result};
use agent_undo_domain::hash::Digest;
use agent_undo_domain::policy::{Insert, SensitiveIds};
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// Most ids remembered per project (64 bytes per line on disk, 32 in memory).
pub const MAX_SENSITIVE_IDS: usize = 200_000;
const FILE_CAP: u64 = (MAX_SENSITIVE_IDS as u64 + 1) * 65;

/// Lazily loaded registry backed by a file.
pub struct FsSensitiveIds {
    path: PathBuf,
    ids: RefCell<Option<SensitiveIds>>,
}

impl FsSensitiveIds {
    pub fn new(path: PathBuf) -> FsSensitiveIds {
        FsSensitiveIds {
            path,
            ids: RefCell::new(None),
        }
    }

    fn load(&self) -> Result<SensitiveIds> {
        match read_small(&self.path, FILE_CAP) {
            Ok(bytes) => {
                let text = String::from_utf8(bytes)
                    .map_err(|_| Error::Format("sensitive-ids is not UTF-8".into()))?;
                Ok(SensitiveIds::decode(&text, MAX_SENSITIVE_IDS)?)
            }
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                Ok(SensitiveIds::new(MAX_SENSITIVE_IDS))
            }
            Err(e) => Err(e),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut SensitiveIds) -> Result<T>) -> Result<T> {
        let mut slot = self.ids.borrow_mut();
        if slot.is_none() {
            *slot = Some(self.load()?);
        }
        match slot.as_mut() {
            Some(ids) => f(ids),
            None => Err(Error::Other("internal error: registry not loaded".into())),
        }
    }

    pub fn contains(&self, id: &Digest) -> Result<bool> {
        self.with(|ids| Ok(ids.contains(id)))
    }

    /// Remembers `id`. With `persist` the id is also appended to the file (fsynced)
    /// so later runs know it; without it (read-only scans under a shared lock) it
    /// only lives for this process.
    pub fn remember(&self, id: Digest, persist: bool) -> Result<Insert> {
        self.with(|ids| {
            let outcome = ids.insert(id);
            if outcome == Insert::Added && persist {
                let mut f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(O_NOFOLLOW)
                    .open(&self.path)
                    .ctx(|| format!("opening {}", display_path(&self.path)))?;
                f.write_all(SensitiveIds::encode_one(&id).as_bytes())
                    .and_then(|()| f.sync_all())
                    .ctx(|| format!("writing {}", display_path(&self.path)))?;
            }
            Ok(outcome)
        })
    }

    pub fn len(&self) -> Result<usize> {
        self.with(|ids| Ok(ids.len()))
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}
