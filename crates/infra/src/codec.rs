//! Line-oriented on-disk formats of manifests and change sets.
//!
//! ```text
//! agent-undo-manifest v1
//! <path>\t<kind>,<mode>,<size>,<mtime_ns>,<ctime_ns>,<id>
//!
//! agent-undo-changes v1
//! <kind>\t<path>\t<before>\t<after>
//! ```
//!
//! Paths and symlink targets are percent encoded, so a hostile name can never
//! inject a separator or newline. Every reader enforces a maximum line length,
//! so a corrupt or hostile file cannot make the parser allocate without bound.
//! Entry and change text forms are defined by the domain crate.

use agent_undo_app::error::{Error, Result};
use agent_undo_app::ports::ChangeStream;
use agent_undo_domain::change::{Change, EntrySource};
use agent_undo_domain::entry::Entry;
use agent_undo_domain::esc::{pct_decode, pct_encode};
use agent_undo_domain::hash::{Digest, Sha256};
use agent_undo_domain::path::RelPath;
use std::io::{self, BufRead, Write};

pub const MANIFEST_HEADER: &str = "agent-undo-manifest v1";
pub const CHANGES_HEADER: &str = "agent-undo-changes v1";
/// Longest accepted line in any store file.
pub const MAX_LINE: usize = 64 * 1024;

/// Reads one `\n`-terminated line into `buf` (without the newline), refusing
/// lines longer than [`MAX_LINE`]. Returns `false` at clean EOF.
pub fn read_capped_line<R: BufRead + ?Sized>(r: &mut R, buf: &mut Vec<u8>) -> io::Result<bool> {
    buf.clear();
    loop {
        let (done, used) = {
            let avail = match r.fill_buf() {
                Ok(a) => a,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if avail.is_empty() {
                if buf.is_empty() {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing final newline",
                ));
            }
            let room = (MAX_LINE + 1).saturating_sub(buf.len()).max(1);
            let window = avail.get(..avail.len().min(room)).unwrap_or(avail);
            match window.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    buf.extend_from_slice(window.get(..i).unwrap_or(&[]));
                    (true, i + 1)
                }
                None => {
                    buf.extend_from_slice(window);
                    (false, window.len())
                }
            }
        };
        r.consume(used);
        if buf.len() > MAX_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "line exceeds maximum length",
            ));
        }
        if done {
            return Ok(true);
        }
    }
}

fn line_str(buf: &[u8]) -> Result<&str> {
    std::str::from_utf8(buf).map_err(|_| Error::Format("store file contains non-UTF-8 text".into()))
}

fn read_err(what: &str, e: io::Error) -> Error {
    Error::io(format!("reading {what}"), e)
}

/// Streaming reader over a manifest file.
pub struct ManifestReader<R: BufRead> {
    r: R,
    buf: Vec<u8>,
    last: Option<RelPath>,
    count: u64,
}

impl<R: BufRead> ManifestReader<R> {
    pub fn new(mut r: R) -> Result<Self> {
        let mut buf = Vec::new();
        if !read_capped_line(&mut r, &mut buf).map_err(|e| read_err("manifest header", e))? {
            return Err(Error::Format("empty manifest".into()));
        }
        if buf != MANIFEST_HEADER.as_bytes() {
            return Err(Error::Format("unrecognised manifest header".into()));
        }
        Ok(ManifestReader {
            r,
            buf,
            last: None,
            count: 0,
        })
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

impl<R: BufRead> EntrySource for ManifestReader<R> {
    type Error = Error;

    /// Next entry, validating path syntax and strictly increasing order.
    fn next_entry(&mut self) -> Result<Option<(RelPath, Entry)>> {
        if !read_capped_line(&mut self.r, &mut self.buf).map_err(|e| read_err("manifest", e))? {
            return Ok(None);
        }
        let line = line_str(&self.buf)?;
        let (path_s, entry_s) = line
            .split_once('\t')
            .ok_or_else(|| Error::Format("manifest line without separator".into()))?;
        let path =
            pct_decode(path_s).ok_or_else(|| Error::Format("manifest path encoding".into()))?;
        let path = RelPath::new(path)?;
        let entry = Entry::decode(entry_s)?;
        if let Some(prev) = &self.last
            && prev >= &path
        {
            return Err(Error::Format("manifest entries are not sorted".into()));
        }
        self.last = Some(path.clone());
        self.count += 1;
        Ok(Some((path, entry)))
    }
}

/// Streaming writer for a manifest file; hashes everything it writes.
pub struct ManifestWriter<W: Write> {
    w: W,
    hasher: Sha256,
    last: Option<RelPath>,
    count: u64,
}

impl<W: Write> ManifestWriter<W> {
    pub fn new(mut w: W) -> Result<Self> {
        let mut hasher = Sha256::new();
        let header = format!("{MANIFEST_HEADER}\n");
        hasher.update(header.as_bytes());
        w.write_all(header.as_bytes())
            .map_err(|e| Error::io("writing manifest", e))?;
        Ok(ManifestWriter {
            w,
            hasher,
            last: None,
            count: 0,
        })
    }

    pub fn write_entry(&mut self, path: &RelPath, entry: &Entry) -> Result<()> {
        if let Some(prev) = &self.last
            && prev >= path
        {
            return Err(Error::Other(
                "internal error: manifest entries out of order".into(),
            ));
        }
        let line = format!("{}\t{}\n", pct_encode(path.as_bytes()), entry.encode());
        self.hasher.update(line.as_bytes());
        self.w
            .write_all(line.as_bytes())
            .map_err(|e| Error::io("writing manifest", e))?;
        self.last = Some(path.clone());
        self.count += 1;
        Ok(())
    }

    /// Flushes and returns the underlying writer, the content hash and entry count.
    pub fn finish(mut self) -> Result<(W, Digest, u64)> {
        self.w
            .flush()
            .map_err(|e| Error::io("flushing manifest", e))?;
        Ok((self.w, self.hasher.finalize(), self.count))
    }
}

/// Streaming reader over a changes file.
pub struct ChangesReader<R: BufRead> {
    r: R,
    buf: Vec<u8>,
}

impl<R: BufRead> ChangesReader<R> {
    pub fn new(mut r: R) -> Result<Self> {
        let mut buf = Vec::new();
        if !read_capped_line(&mut r, &mut buf).map_err(|e| read_err("changes header", e))? {
            return Err(Error::Format("empty changes file".into()));
        }
        if buf != CHANGES_HEADER.as_bytes() {
            return Err(Error::Format("unrecognised changes header".into()));
        }
        Ok(ChangesReader { r, buf })
    }
}

impl<R: BufRead> ChangeStream for ChangesReader<R> {
    fn next_change(&mut self) -> Result<Option<Change>> {
        if !read_capped_line(&mut self.r, &mut self.buf).map_err(|e| read_err("changes", e))? {
            return Ok(None);
        }
        Ok(Some(Change::decode(line_str(&self.buf)?)?))
    }
}

/// Streaming writer for a changes file; hashes everything it writes.
pub struct ChangesWriter<W: Write> {
    w: W,
    hasher: Sha256,
    count: u64,
}

impl<W: Write> ChangesWriter<W> {
    pub fn new(mut w: W) -> Result<Self> {
        let mut hasher = Sha256::new();
        let header = format!("{CHANGES_HEADER}\n");
        hasher.update(header.as_bytes());
        w.write_all(header.as_bytes())
            .map_err(|e| Error::io("writing changes", e))?;
        Ok(ChangesWriter {
            w,
            hasher,
            count: 0,
        })
    }

    pub fn write_change(&mut self, c: &Change) -> Result<()> {
        let line = format!("{}\n", c.encode());
        self.hasher.update(line.as_bytes());
        self.w
            .write_all(line.as_bytes())
            .map_err(|e| Error::io("writing changes", e))?;
        self.count += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(W, Digest, u64)> {
        self.w
            .flush()
            .map_err(|e| Error::io("flushing changes", e))?;
        Ok((self.w, self.hasher.finalize(), self.count))
    }
}

#[cfg(test)]
mod tests;
