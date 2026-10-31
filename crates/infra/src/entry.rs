//! Manifest entries, change records and their line-oriented on-disk formats.
//!
//! Manifest file (`NNNNNNNN.manifest`):
//!
//! ```text
//! agent-undo-manifest v1
//! <path>\t<kind>,<mode>,<size>,<mtime_ns>,<ctime_ns>,<id>
//! ```
//!
//! Entries are sorted by [`crate::paths::cmp_paths`] so two manifests can be
//! compared in one streaming merge. Paths and symlink targets are percent
//! encoded, so a hostile name can never inject a separator or newline.
//! Every reader enforces a maximum line length; a corrupt or hostile file cannot
//! make the parser allocate without bound.

use crate::error::{Error, Result};
use crate::paths::{cmp_paths, validate_rel};
use agent_undo_domain::esc::{pct_decode, pct_encode};
use agent_undo_domain::hash::{Digest, Sha256, digest_from_hex, to_hex};
use std::cmp::Ordering;
use std::io::{self, BufRead, Write};

pub const MANIFEST_HEADER: &str = "agent-undo-manifest v1";
pub const CHANGES_HEADER: &str = "agent-undo-changes v1";
/// Longest accepted line in any store file.
pub const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Regular file whose content is stored as a blob.
    File,
    /// Regular file above the size cap: hash only, cannot be restored.
    TooLarge,
    /// Sensitive file: size and keyed hash-of-hash only.
    Sensitive,
    Symlink,
    Dir,
    /// FIFO, socket, device: never opened, never touched by undo.
    Special,
    /// Could not be read (permissions, changed while reading).
    Unreadable,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::File => "file",
            Kind::TooLarge => "too-large",
            Kind::Sensitive => "sensitive",
            Kind::Symlink => "symlink",
            Kind::Dir => "dir",
            Kind::Special => "special",
            Kind::Unreadable => "unreadable",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "file" => Kind::File,
            "too-large" => Kind::TooLarge,
            "sensitive" => Kind::Sensitive,
            "symlink" => Kind::Symlink,
            "dir" => Kind::Dir,
            "special" => Kind::Special,
            "unreadable" => Kind::Unreadable,
            _ => return None,
        })
    }

    fn id_is_digest(self) -> bool {
        matches!(self, Kind::File | Kind::TooLarge | Kind::Sensitive)
    }
}

/// The recorded state of one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    /// Permission bits (`mode & 0o7777`).
    pub mode: u32,
    pub size: u64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    /// `File`/`TooLarge`: SHA-256 of the content. `Sensitive`: HMAC-SHA-256 of that
    /// hash under the store key. `Symlink`: the raw link target. Otherwise empty.
    pub id: Vec<u8>,
}

impl Entry {
    pub fn dir(mode: u32, mtime_ns: i64, ctime_ns: i64) -> Entry {
        Entry {
            kind: Kind::Dir,
            mode: mode & 0o7777,
            size: 0,
            mtime_ns,
            ctime_ns,
            id: Vec::new(),
        }
    }

    /// Digest for kinds whose id is a hash.
    pub fn digest(&self) -> Option<Digest> {
        if self.kind.id_is_digest() {
            self.id.as_slice().try_into().ok()
        } else {
            None
        }
    }

    /// Blob id of a restorable regular file.
    pub fn blob(&self) -> Option<Digest> {
        if self.kind == Kind::File {
            self.digest()
        } else {
            None
        }
    }

    /// Link target of a symlink entry.
    pub fn target(&self) -> Option<&[u8]> {
        (self.kind == Kind::Symlink).then_some(self.id.as_slice())
    }

    /// Equality of everything that matters for "did this change": kind, size,
    /// content id and permission bits (not timestamps; symlink modes are ignored).
    pub fn semantic_eq(&self, other: &Entry) -> bool {
        self.kind == other.kind
            && self.size == other.size
            && self.id == other.id
            && (self.kind == Kind::Symlink || self.mode == other.mode)
    }

    /// Whether content (not just mode) is identical.
    pub fn same_content(&self, other: &Entry) -> bool {
        self.kind == other.kind && self.size == other.size && self.id == other.id
    }

    pub fn encode(&self) -> String {
        let id = if self.kind.id_is_digest() {
            to_hex(&self.id)
        } else if self.id.is_empty() {
            "-".to_string()
        } else {
            pct_encode(&self.id)
        };
        format!(
            "{},{:o},{},{},{},{}",
            self.kind.as_str(),
            self.mode,
            self.size,
            self.mtime_ns,
            self.ctime_ns,
            id
        )
    }

    pub fn decode(s: &str) -> Result<Entry> {
        let bad = |why: &str| Error::Format(format!("bad entry {s:?}: {why}"));
        let mut it = s.split(',');
        let kind = Kind::parse(it.next().ok_or_else(|| bad("missing kind"))?)
            .ok_or_else(|| bad("unknown kind"))?;
        let mode = u32::from_str_radix(it.next().ok_or_else(|| bad("missing mode"))?, 8)
            .map_err(|_| bad("mode"))?;
        let size: u64 = it
            .next()
            .ok_or_else(|| bad("missing size"))?
            .parse()
            .map_err(|_| bad("size"))?;
        let mtime_ns: i64 = it
            .next()
            .ok_or_else(|| bad("missing mtime"))?
            .parse()
            .map_err(|_| bad("mtime"))?;
        let ctime_ns: i64 = it
            .next()
            .ok_or_else(|| bad("missing ctime"))?
            .parse()
            .map_err(|_| bad("ctime"))?;
        let id_s = it.next().ok_or_else(|| bad("missing id"))?;
        if it.next().is_some() {
            return Err(bad("too many fields"));
        }
        if mode > 0o7777 {
            return Err(bad("mode out of range"));
        }
        let id = if kind.id_is_digest() {
            digest_from_hex(id_s)
                .ok_or_else(|| bad("id is not a 64-char hex digest"))?
                .to_vec()
        } else if id_s == "-" {
            Vec::new()
        } else {
            pct_decode(id_s).ok_or_else(|| bad("id encoding"))?
        };
        if kind == Kind::Symlink && id.is_empty() {
            return Err(bad("symlink without target"));
        }
        if !kind.id_is_digest() && kind != Kind::Symlink && !id.is_empty() {
            return Err(bad("unexpected id"));
        }
        Ok(Entry {
            kind,
            mode,
            size,
            mtime_ns,
            ctime_ns,
            id,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Created,
    Deleted,
    Modified,
    ModeChanged,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Created => "created",
            ChangeKind::Deleted => "deleted",
            ChangeKind::Modified => "modified",
            ChangeKind::ModeChanged => "mode-changed",
        }
    }

    pub fn parse(s: &str) -> Option<ChangeKind> {
        Some(match s {
            "created" => ChangeKind::Created,
            "deleted" => ChangeKind::Deleted,
            "modified" => ChangeKind::Modified,
            "mode-changed" => ChangeKind::ModeChanged,
            _ => return None,
        })
    }
}

/// Classifies the difference between two states of the same path.
pub fn classify(before: Option<&Entry>, after: Option<&Entry>) -> Option<ChangeKind> {
    match (before, after) {
        (None, None) => None,
        (None, Some(_)) => Some(ChangeKind::Created),
        (Some(_), None) => Some(ChangeKind::Deleted),
        (Some(b), Some(a)) => {
            if b.semantic_eq(a) {
                None
            } else if b.same_content(a) {
                Some(ChangeKind::ModeChanged)
            } else {
                Some(ChangeKind::Modified)
            }
        }
    }
}

/// One path whose state differs between two points in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    pub path: Vec<u8>,
    pub before: Option<Entry>,
    pub after: Option<Entry>,
}

fn encode_opt(e: &Option<Entry>) -> String {
    e.as_ref().map_or_else(|| "-".to_string(), Entry::encode)
}

fn decode_opt(s: &str) -> Result<Option<Entry>> {
    if s == "-" {
        Ok(None)
    } else {
        Entry::decode(s).map(Some)
    }
}

impl Change {
    pub fn new(path: Vec<u8>, before: Option<Entry>, after: Option<Entry>) -> Option<Change> {
        let kind = classify(before.as_ref(), after.as_ref())?;
        Some(Change {
            kind,
            path,
            before,
            after,
        })
    }

    pub fn encode(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.kind.as_str(),
            pct_encode(&self.path),
            encode_opt(&self.before),
            encode_opt(&self.after)
        )
    }

    pub fn decode(line: &str) -> Result<Change> {
        let bad = |why: &str| Error::Format(format!("bad change record: {why}"));
        let mut it = line.split('\t');
        let kind = ChangeKind::parse(it.next().ok_or_else(|| bad("missing type"))?)
            .ok_or_else(|| bad("unknown type"))?;
        let path = pct_decode(it.next().ok_or_else(|| bad("missing path"))?)
            .ok_or_else(|| bad("path encoding"))?;
        validate_rel(&path)?;
        let before = decode_opt(it.next().ok_or_else(|| bad("missing before"))?)?;
        let after = decode_opt(it.next().ok_or_else(|| bad("missing after"))?)?;
        if it.next().is_some() {
            return Err(bad("too many fields"));
        }
        if classify(before.as_ref(), after.as_ref()) != Some(kind) {
            return Err(bad("type does not match before/after"));
        }
        Ok(Change {
            kind,
            path,
            before,
            after,
        })
    }
}

/// Reads one `\n`-terminated line into `buf` (without the newline), refusing
/// lines longer than [`MAX_LINE`]. Returns `false` at clean EOF.
pub fn read_capped_line<R: BufRead>(r: &mut R, buf: &mut Vec<u8>) -> io::Result<bool> {
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
    last: Option<Vec<u8>>,
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

    /// Next entry, validating path syntax and strictly increasing order.
    pub fn next_entry(&mut self) -> Result<Option<(Vec<u8>, Entry)>> {
        if !read_capped_line(&mut self.r, &mut self.buf).map_err(|e| read_err("manifest", e))? {
            return Ok(None);
        }
        let line = line_str(&self.buf)?;
        let (path_s, entry_s) = line
            .split_once('\t')
            .ok_or_else(|| Error::Format("manifest line without separator".into()))?;
        let path =
            pct_decode(path_s).ok_or_else(|| Error::Format("manifest path encoding".into()))?;
        validate_rel(&path)?;
        let entry = Entry::decode(entry_s)?;
        if let Some(prev) = &self.last
            && cmp_paths(prev, &path) != Ordering::Less
        {
            return Err(Error::Format("manifest entries are not sorted".into()));
        }
        self.last = Some(path.clone());
        self.count += 1;
        Ok(Some((path, entry)))
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

/// Streaming writer for a manifest file; hashes everything it writes.
pub struct ManifestWriter<W: Write> {
    w: W,
    hasher: Sha256,
    last: Option<Vec<u8>>,
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

    pub fn write_entry(&mut self, path: &[u8], entry: &Entry) -> Result<()> {
        if let Some(prev) = &self.last
            && cmp_paths(prev, path) != Ordering::Less
        {
            return Err(Error::Other(
                "internal error: manifest entries out of order".into(),
            ));
        }
        let line = format!("{}\t{}\n", pct_encode(path), entry.encode());
        self.hasher.update(line.as_bytes());
        self.w
            .write_all(line.as_bytes())
            .map_err(|e| Error::io("writing manifest", e))?;
        self.last = Some(path.to_vec());
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

    pub fn next_change(&mut self) -> Result<Option<Change>> {
        if !read_capped_line(&mut self.r, &mut self.buf).map_err(|e| read_err("changes", e))? {
            return Ok(None);
        }
        Change::decode(line_str(&self.buf)?).map(Some)
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
mod tests {
    use super::*;
    use agent_undo_domain::hash::sha256;
    use std::io::Cursor;

    fn file_entry(content: &[u8], mode: u32) -> Entry {
        Entry {
            kind: Kind::File,
            mode,
            size: content.len() as u64,
            mtime_ns: 10,
            ctime_ns: 20,
            id: sha256(content).to_vec(),
        }
    }

    #[test]
    fn entry_round_trip_all_kinds() {
        let entries = [
            file_entry(b"x", 0o644),
            Entry {
                kind: Kind::TooLarge,
                ..file_entry(b"big", 0o600)
            },
            Entry {
                kind: Kind::Sensitive,
                ..file_entry(b"s", 0o600)
            },
            Entry {
                kind: Kind::Symlink,
                mode: 0o777,
                size: 4,
                mtime_ns: -5,
                ctime_ns: 0,
                id: b"../a b,c\n".to_vec(),
            },
            Entry::dir(0o755, 1, 2),
            Entry {
                kind: Kind::Special,
                mode: 0o600,
                size: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                id: vec![],
            },
            Entry {
                kind: Kind::Unreadable,
                mode: 0,
                size: 7,
                mtime_ns: 0,
                ctime_ns: 0,
                id: vec![],
            },
        ];
        for e in entries {
            let enc = e.encode();
            assert!(!enc.contains('\n') && !enc.contains('\t'));
            assert_eq!(Entry::decode(&enc).unwrap(), e, "{enc}");
        }
    }

    #[test]
    fn entry_decode_rejects_garbage() {
        let good = file_entry(b"x", 0o644).encode();
        assert!(Entry::decode("").is_err());
        assert!(Entry::decode("file,644,1,2,3").is_err());
        assert!(Entry::decode(&format!("{good},extra")).is_err());
        assert!(Entry::decode("nope,644,1,2,3,-").is_err());
        assert!(Entry::decode("file,999,1,2,3,00").is_err());
        assert!(Entry::decode("file,10000,1,2,3,00").is_err());
        assert!(Entry::decode("file,644,x,2,3,00").is_err());
        assert!(Entry::decode("symlink,777,1,2,3,-").is_err());
        assert!(Entry::decode("dir,755,0,2,3,abcd").is_err());
        let short = good.rsplit_once(',').unwrap().0.to_string() + ",abcd";
        assert!(Entry::decode(&short).is_err());
    }

    #[test]
    fn semantic_equality_ignores_timestamps_but_not_mode() {
        let a = file_entry(b"x", 0o644);
        let mut b = a.clone();
        b.mtime_ns = 999;
        b.ctime_ns = 999;
        assert!(a.semantic_eq(&b));
        b.mode = 0o755;
        assert!(!a.semantic_eq(&b));
        assert!(a.same_content(&b));
    }

    #[test]
    fn symlink_mode_is_ignored() {
        let mut a = Entry {
            kind: Kind::Symlink,
            mode: 0o777,
            size: 1,
            mtime_ns: 0,
            ctime_ns: 0,
            id: b"t".to_vec(),
        };
        let mut b = a.clone();
        b.mode = 0o755;
        assert!(a.semantic_eq(&b));
        a.id = b"u".to_vec();
        assert!(!a.semantic_eq(&b));
    }

    #[test]
    fn classify_cases() {
        let a = file_entry(b"x", 0o644);
        let b = file_entry(b"y", 0o644);
        let mut c = a.clone();
        c.mode = 0o755;
        assert_eq!(classify(None, None), None);
        assert_eq!(classify(None, Some(&a)), Some(ChangeKind::Created));
        assert_eq!(classify(Some(&a), None), Some(ChangeKind::Deleted));
        assert_eq!(classify(Some(&a), Some(&b)), Some(ChangeKind::Modified));
        assert_eq!(classify(Some(&a), Some(&c)), Some(ChangeKind::ModeChanged));
        assert_eq!(classify(Some(&a), Some(&a)), None);
    }

    #[test]
    fn change_round_trip_with_hostile_path() {
        let a = file_entry(b"x", 0o644);
        let path = b"dir/we ird\tna\nme\x1b[31m\xff".to_vec();
        let c = Change::new(path.clone(), Some(a.clone()), None).unwrap();
        let line = c.encode();
        assert!(!line.contains('\n'));
        assert_eq!(Change::decode(&line).unwrap(), c);
        assert_eq!(Change::decode(&line).unwrap().path, path);
    }

    #[test]
    fn change_decode_rejects_traversal_and_mismatch() {
        let a = file_entry(b"x", 0o644).encode();
        assert!(Change::decode(&format!("deleted\t../etc/passwd\t{a}\t-")).is_err());
        assert!(Change::decode(&format!("deleted\t/abs\t{a}\t-")).is_err());
        assert!(Change::decode(&format!("created\ta\t{a}\t-")).is_err());
        assert!(Change::decode("deleted\ta").is_err());
    }

    #[test]
    fn manifest_round_trip_and_hash_is_stable() {
        let mut w = ManifestWriter::new(Vec::new()).unwrap();
        w.write_entry(b"a", &Entry::dir(0o755, 1, 1)).unwrap();
        w.write_entry(b"a/b", &file_entry(b"1", 0o644)).unwrap();
        w.write_entry(b"a-b", &file_entry(b"2", 0o600)).unwrap();
        let (bytes, digest, count) = w.finish().unwrap();
        assert_eq!(count, 3);
        assert_eq!(digest, sha256(&bytes));
        let mut r = ManifestReader::new(Cursor::new(bytes)).unwrap();
        let mut paths = Vec::new();
        while let Some((p, _)) = r.next_entry().unwrap() {
            paths.push(p);
        }
        assert_eq!(paths, vec![b"a".to_vec(), b"a/b".to_vec(), b"a-b".to_vec()]);
        assert_eq!(r.count(), 3);
    }

    #[test]
    fn manifest_writer_rejects_out_of_order() {
        let mut w = ManifestWriter::new(Vec::new()).unwrap();
        w.write_entry(b"b", &Entry::dir(0o755, 1, 1)).unwrap();
        assert!(w.write_entry(b"a", &Entry::dir(0o755, 1, 1)).is_err());
        assert!(w.write_entry(b"b", &Entry::dir(0o755, 1, 1)).is_err());
    }

    #[test]
    fn manifest_reader_rejects_unsorted_and_bad_header() {
        let e = Entry::dir(0o755, 1, 1).encode();
        let text = format!("{MANIFEST_HEADER}\nb\t{e}\na\t{e}\n");
        let mut r = ManifestReader::new(Cursor::new(text.into_bytes())).unwrap();
        r.next_entry().unwrap();
        assert!(r.next_entry().is_err());
        assert!(ManifestReader::new(Cursor::new(b"nope\n".to_vec())).is_err());
        assert!(ManifestReader::new(Cursor::new(Vec::new())).is_err());
    }

    #[test]
    fn manifest_reader_rejects_traversal_paths() {
        let e = Entry::dir(0o755, 1, 1).encode();
        for p in ["..%2Fx", "a/../b", "/abs", "a//b"] {
            let text = format!("{MANIFEST_HEADER}\n{p}\t{e}\n");
            let mut r = ManifestReader::new(Cursor::new(text.into_bytes())).unwrap();
            assert!(r.next_entry().is_err(), "{p}");
        }
        let text = format!("{MANIFEST_HEADER}\n../x\t{e}\n");
        let mut r = ManifestReader::new(Cursor::new(text.into_bytes())).unwrap();
        assert!(r.next_entry().is_err());
    }

    #[test]
    fn capped_line_reader_bounds_memory() {
        let mut data = vec![b'a'; MAX_LINE * 3];
        data.push(b'\n');
        let mut cur = Cursor::new(data);
        let mut buf = Vec::new();
        assert!(read_capped_line(&mut cur, &mut buf).is_err());
        assert!(
            buf.len() <= MAX_LINE * 2,
            "buffer must not hold the whole oversized line"
        );
    }

    #[test]
    fn capped_line_reader_basic() {
        let mut cur = Cursor::new(b"one\ntwo\n".to_vec());
        let mut buf = Vec::new();
        assert!(read_capped_line(&mut cur, &mut buf).unwrap());
        assert_eq!(buf, b"one");
        assert!(read_capped_line(&mut cur, &mut buf).unwrap());
        assert_eq!(buf, b"two");
        assert!(!read_capped_line(&mut cur, &mut buf).unwrap());
        let mut cur = Cursor::new(b"unterminated".to_vec());
        assert!(read_capped_line(&mut cur, &mut buf).is_err());
    }

    #[test]
    fn changes_round_trip() {
        let a = file_entry(b"x", 0o644);
        let b = file_entry(b"y", 0o644);
        let mut w = ChangesWriter::new(Vec::new()).unwrap();
        w.write_change(&Change::new(b"f".to_vec(), Some(a.clone()), Some(b.clone())).unwrap())
            .unwrap();
        w.write_change(&Change::new(b"g".to_vec(), None, Some(a.clone())).unwrap())
            .unwrap();
        let (bytes, digest, count) = w.finish().unwrap();
        assert_eq!(count, 2);
        assert_eq!(digest, sha256(&bytes));
        let mut r = ChangesReader::new(Cursor::new(bytes)).unwrap();
        let c1 = r.next_change().unwrap().unwrap();
        assert_eq!(c1.kind, ChangeKind::Modified);
        let c2 = r.next_change().unwrap().unwrap();
        assert_eq!(c2.kind, ChangeKind::Created);
        assert!(r.next_change().unwrap().is_none());
    }
}
