//! Filesystem journal repository: an append-only `log` file of hash-chained
//! records plus a `pruned` list.

use crate::codec::{MAX_LINE, read_capped_line};
use crate::fsutil::O_NOFOLLOW;
use crate::fsutil::display_path;
use crate::layout::read_small;
use agent_undo_app::error::{Ctx, Error, Result};
use agent_undo_app::ports::JournalRepository;
use agent_undo_domain::journal::{CheckpointId, CheckpointRecord, Journal};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

const MAX_LOG_ENTRIES: usize = 1_000_000;

pub struct FsJournal {
    log: PathBuf,
    pruned: PathBuf,
}

impl FsJournal {
    pub fn new(log: PathBuf, pruned: PathBuf) -> FsJournal {
        FsJournal { log, pruned }
    }

    fn read_pruned(&self) -> Result<BTreeSet<u64>> {
        let text = match read_small(&self.pruned, 16 * 1024 * 1024) {
            Ok(t) => t,
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeSet::new());
            }
            Err(e) => return Err(e),
        };
        let text = String::from_utf8(text)
            .map_err(|_| Error::Integrity("pruned list is not UTF-8".into()))?;
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                l.parse::<u64>()
                    .map_err(|_| Error::Integrity("bad pruned list".into()))
            })
            .collect()
    }
}

impl JournalRepository for FsJournal {
    fn load(&self) -> Result<Journal> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(&self.log)
            .ctx(|| format!("opening {}", display_path(&self.log)))?;
        let mut r = BufReader::new(file);
        let mut buf = Vec::new();
        let mut records = Vec::new();
        while read_capped_line(&mut r, &mut buf)
            .map_err(|e| Error::Integrity(format!("reading log: {e}")))?
        {
            if records.len() >= MAX_LOG_ENTRIES {
                return Err(Error::Limit("log has too many entries".into()));
            }
            let line = std::str::from_utf8(&buf)
                .map_err(|_| Error::Integrity("log contains non-UTF-8 data".into()))?;
            let n = records.len() + 1;
            records.push(
                CheckpointRecord::decode(line)
                    .map_err(|e| Error::Integrity(format!("log entry {n}: {e}")))?,
            );
        }
        Ok(Journal::from_records(records, self.read_pruned()?)?)
    }

    fn append(&self, record: &CheckpointRecord) -> Result<()> {
        let mut line = record.encode();
        line.push('\n');
        if line.len() > MAX_LINE {
            return Err(Error::Limit("log record too large".into()));
        }
        let mut f = OpenOptions::new()
            .append(true)
            .custom_flags(O_NOFOLLOW)
            .open(&self.log)
            .ctx(|| "opening log for append".into())?;
        f.write_all(line.as_bytes())
            .and_then(|()| f.sync_all())
            .ctx(|| "appending to log".into())
    }

    fn save_pruned(&self, ids: &[CheckpointId]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&self.pruned)
            .ctx(|| "opening pruned list".into())?;
        let text: String = ids.iter().map(|i| format!("{}\n", i.get())).collect();
        f.write_all(text.as_bytes())
            .and_then(|()| f.sync_all())
            .ctx(|| "writing pruned list".into())
    }
}
