//! Filesystem blob store: `blobs/ab/<sha256>`, written through temp files.

use crate::fsutil::{create_new_private, create_private_dir_all, display_path, unique_suffix};
use agent_undo_app::error::{Ctx, Error, Result};
use agent_undo_app::ports::{BlobListing, BlobStore, BlobWriter};
use agent_undo_domain::hash::{Digest, Sha256, digest_from_hex, to_hex};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct FsBlobs {
    blobs_dir: PathBuf,
    tmp_dir: PathBuf,
}

impl FsBlobs {
    pub fn new(blobs_dir: PathBuf, tmp_dir: PathBuf) -> FsBlobs {
        FsBlobs { blobs_dir, tmp_dir }
    }

    pub fn path_of(&self, d: &Digest) -> PathBuf {
        let hex = to_hex(d);
        self.blobs_dir.join(hex.get(..2).unwrap_or("00")).join(&hex)
    }

    fn open(&self, d: &Digest) -> Result<File> {
        File::open(self.path_of(d)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Integrity(format!("blob {} is missing from the store", to_hex(d)))
            } else {
                Error::io(format!("opening blob {}", to_hex(d)), e)
            }
        })
    }
}

struct FsBlobWriter {
    file: Option<File>,
    tmp: PathBuf,
    store: FsBlobs,
    hasher: Sha256,
}

impl BlobWriter for FsBlobWriter {
    fn write(&mut self, chunk: &[u8]) -> Result<()> {
        self.hasher.update(chunk);
        match self.file.as_mut() {
            Some(f) => f.write_all(chunk).ctx(|| "writing blob".into()),
            None => Err(Error::Other("blob writer already finished".into())),
        }
    }

    fn commit(mut self: Box<Self>, expected: &Digest) -> Result<bool> {
        let actual = self.hasher.clone().finalize();
        if let Some(f) = self.file.take() {
            f.sync_all().ctx(|| "syncing blob".into())?;
        }
        if &actual != expected {
            let _ = fs::remove_file(&self.tmp);
            return Ok(false);
        }
        let dest = self.store.path_of(expected);
        if let Some(parent) = dest.parent() {
            create_private_dir_all(parent)?;
        }
        fs::rename(&self.tmp, &dest).ctx(|| "storing blob".into())?;
        Ok(true)
    }
}

impl Drop for FsBlobWriter {
    fn drop(&mut self) {
        // Not committed: remove the temp file (after a commit the file was renamed away).
        if self.file.is_some() || self.tmp.exists() {
            self.file = None;
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

impl BlobStore for FsBlobs {
    fn contains(&self, digest: &Digest) -> bool {
        fs::symlink_metadata(self.path_of(digest)).is_ok_and(|m| m.is_file())
    }

    fn read(&self, digest: &Digest, cap: u64) -> Result<Vec<u8>> {
        let f = self.open(digest)?;
        let mut buf = Vec::new();
        f.take(cap.saturating_add(1))
            .read_to_end(&mut buf)
            .ctx(|| format!("reading blob {}", to_hex(digest)))?;
        if buf.len() as u64 > cap {
            return Err(Error::Limit(format!(
                "blob {} larger than {cap} bytes",
                to_hex(digest)
            )));
        }
        Ok(buf)
    }

    fn hash_stored(&self, digest: &Digest) -> Result<Digest> {
        let mut f = self.open(digest)?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f
                .read(&mut buf)
                .ctx(|| format!("reading blob {}", to_hex(digest)))?;
            if n == 0 {
                break;
            }
            h.update(buf.get(..n).unwrap_or(&[]));
        }
        Ok(h.finalize())
    }

    fn list(&self) -> Result<BlobListing> {
        let mut listing = BlobListing::default();
        let mut shards: Vec<PathBuf> = fs::read_dir(&self.blobs_dir)
            .ctx(|| "listing blobs".into())?
            .filter_map(std::result::Result::ok)
            .map(|e| e.path())
            .collect();
        shards.sort();
        let name_of = |p: &Path| {
            p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        for shard in shards {
            if !shard.is_dir() {
                listing.strays.push(name_of(&shard));
                continue;
            }
            let mut files: Vec<PathBuf> = fs::read_dir(&shard)
                .ctx(|| format!("listing {}", display_path(&shard)))?
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .collect();
            files.sort();
            for f in files {
                let name = name_of(&f);
                let md = fs::symlink_metadata(&f).ok();
                match digest_from_hex(&name) {
                    Some(d)
                        if md.as_ref().is_some_and(fs::Metadata::is_file)
                            && name_of(&shard) == name.get(..2).unwrap_or("") =>
                    {
                        listing.blobs.push((d, md.map_or(0, |m| m.len())));
                    }
                    _ => listing.strays.push(format!("{}/{name}", name_of(&shard))),
                }
            }
        }
        Ok(listing)
    }

    fn remove(&self, digest: &Digest) -> Result<()> {
        match fs::remove_file(self.path_of(digest)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::io(format!("removing blob {}", to_hex(digest)), e)),
        }
    }

    fn writer(&self) -> Result<Box<dyn BlobWriter>> {
        let tmp = self.tmp_dir.join(format!("blob-{}", unique_suffix()));
        let file = create_new_private(&tmp).ctx(|| "creating temp blob".into())?;
        Ok(Box::new(FsBlobWriter {
            file: Some(file),
            tmp,
            store: self.clone(),
            hasher: Sha256::new(),
        }))
    }
}
