//! Filesystem snapshot repository: manifests and change sets under
//! `checkpoints/`, written through temp files and renamed into place.

use crate::codec::{ChangesReader, ChangesWriter, ManifestReader, ManifestWriter};
use crate::fsutil::{create_new_private, display_path, sync_dir, unique_suffix};
use agent_undo_app::error::{Ctx, Error, Result};
use agent_undo_app::ports::{
    ChangeStream, CheckpointWriter, ManifestStream, SnapshotRepository, StoredDigests, Written,
};
use agent_undo_domain::change::Change;
use agent_undo_domain::entry::Entry;
use agent_undo_domain::hash::{Digest, Sha256};
use agent_undo_domain::journal::CheckpointId;
use agent_undo_domain::path::RelPath;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};

const BUF_SIZE: usize = 64 * 1024;

pub struct FsSnapshots {
    dir: PathBuf,
    tmp: PathBuf,
}

impl FsSnapshots {
    pub fn new(checkpoints_dir: PathBuf, tmp_dir: PathBuf) -> FsSnapshots {
        FsSnapshots {
            dir: checkpoints_dir,
            tmp: tmp_dir,
        }
    }

    pub fn manifest_path(&self, id: CheckpointId) -> PathBuf {
        self.dir.join(format!("{:08}.manifest", id.get()))
    }

    pub fn changes_path(&self, id: CheckpointId) -> PathBuf {
        self.dir.join(format!("{:08}.changes", id.get()))
    }
}

fn open_for(path: &Path, what: &str, id: CheckpointId) -> Result<File> {
    File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Integrity(format!(
                "{what} of checkpoint {id} is missing (pruned or deleted)"
            ))
        } else {
            Error::io(format!("opening {what} of checkpoint {id}"), e)
        }
    })
}

fn hash_file(path: &Path) -> Result<Digest> {
    let mut f = File::open(path).ctx(|| format!("opening {}", display_path(path)))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = f
            .read(&mut buf)
            .ctx(|| format!("reading {}", display_path(path)))?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or(&[]));
    }
    Ok(h.finalize())
}

struct FsWriter {
    manifest: Option<ManifestWriter<BufWriter<File>>>,
    changes: Option<ChangesWriter<BufWriter<File>>>,
    tmp_manifest: PathBuf,
    tmp_changes: PathBuf,
    final_manifest: PathBuf,
    final_changes: PathBuf,
    dir: PathBuf,
    done: bool,
}

fn finish_file(w: BufWriter<File>, what: &str) -> Result<()> {
    let f = w
        .into_inner()
        .map_err(|e| Error::io(format!("flushing {what}"), e.into_error()))?;
    f.sync_all().ctx(|| format!("syncing {what}"))
}

impl CheckpointWriter for FsWriter {
    fn write_entry(&mut self, path: &RelPath, entry: &Entry) -> Result<()> {
        match self.manifest.as_mut() {
            Some(m) => m.write_entry(path, entry),
            None => Err(Error::Other("checkpoint writer already finished".into())),
        }
    }

    fn write_change(&mut self, change: &Change) -> Result<()> {
        match self.changes.as_mut() {
            Some(c) => c.write_change(change),
            None => Err(Error::Other("checkpoint writer already finished".into())),
        }
    }

    fn commit(mut self: Box<Self>) -> Result<Written> {
        let (Some(m), Some(c)) = (self.manifest.take(), self.changes.take()) else {
            return Err(Error::Other("checkpoint writer already finished".into()));
        };
        let (mw, manifest, entries) = m.finish()?;
        let (cw, changes, _) = c.finish()?;
        finish_file(mw, "manifest")?;
        finish_file(cw, "change set")?;
        fs::rename(&self.tmp_manifest, &self.final_manifest)
            .ctx(|| "installing manifest".into())?;
        fs::rename(&self.tmp_changes, &self.final_changes)
            .ctx(|| "installing change set".into())?;
        self.done = true;
        sync_dir(&self.dir);
        Ok(Written {
            manifest,
            changes,
            entries,
        })
    }
}

impl Drop for FsWriter {
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_file(&self.tmp_manifest);
            let _ = fs::remove_file(&self.tmp_changes);
        }
    }
}

impl SnapshotRepository for FsSnapshots {
    fn open_manifest(&self, id: CheckpointId) -> Result<ManifestStream> {
        let f = open_for(&self.manifest_path(id), "manifest", id)?;
        Ok(Box::new(ManifestReader::new(BufReader::new(f))?))
    }

    fn open_changes(&self, id: CheckpointId) -> Result<Box<dyn ChangeStream>> {
        let f = open_for(&self.changes_path(id), "change set", id)?;
        Ok(Box::new(ChangesReader::new(BufReader::new(f))?))
    }

    fn begin(&self, id: CheckpointId) -> Result<Box<dyn CheckpointWriter>> {
        let suffix = unique_suffix();
        let tmp_manifest = self.tmp.join(format!("manifest-{suffix}"));
        let tmp_changes = self.tmp.join(format!("changes-{suffix}"));
        let mf = create_new_private(&tmp_manifest).ctx(|| "creating temp manifest".into())?;
        let cf = match create_new_private(&tmp_changes) {
            Ok(f) => f,
            Err(e) => {
                let _ = fs::remove_file(&tmp_manifest);
                return Err(Error::io("creating temp change set", e));
            }
        };
        let manifest = ManifestWriter::new(BufWriter::with_capacity(BUF_SIZE, mf))?;
        let changes = ChangesWriter::new(BufWriter::with_capacity(BUF_SIZE, cf))?;
        Ok(Box::new(FsWriter {
            manifest: Some(manifest),
            changes: Some(changes),
            tmp_manifest,
            tmp_changes,
            final_manifest: self.manifest_path(id),
            final_changes: self.changes_path(id),
            dir: self.dir.clone(),
            done: false,
        }))
    }

    fn remove(&self, id: CheckpointId) -> Result<()> {
        for p in [self.manifest_path(id), self.changes_path(id)] {
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::io(format!("removing {}", display_path(&p)), e)),
            }
        }
        Ok(())
    }

    fn stored_digests(&self, id: CheckpointId) -> Result<StoredDigests> {
        let m = self.manifest_path(id);
        let c = self.changes_path(id);
        for (p, what) in [(&m, "manifest"), (&c, "change set")] {
            if !p.is_file() {
                return Err(Error::Integrity(format!(
                    "{what} of checkpoint {id} is missing"
                )));
            }
        }
        Ok(StoredDigests {
            manifest: hash_file(&m)?,
            changes: hash_file(&c)?,
        })
    }

    fn list(&self) -> Result<Vec<CheckpointId>> {
        let mut ids: Vec<u64> = fs::read_dir(&self.dir)
            .ctx(|| "listing checkpoints".into())?
            .filter_map(std::result::Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let stem = name
                    .strip_suffix(".manifest")
                    .or_else(|| name.strip_suffix(".changes"))?;
                stem.parse::<u64>().ok()
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        Ok(ids
            .into_iter()
            .filter_map(|i| CheckpointId::new(i).ok())
            .collect())
    }
}
