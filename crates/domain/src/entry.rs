//! `Entry`: the recorded state of one path, plus its canonical text form.
//!
//! The canonical text form (`kind,mode,size,mtime_ns,ctime_ns,id`) is part of
//! the domain because change-set and manifest hashes are computed over it.

use crate::error::{DomainError, DomainResult};
use crate::esc::{pct_decode, pct_encode};
use crate::hash::{Digest, digest_from_hex, to_hex};

/// Longest symlink target that is recorded.
pub const MAX_LINK_TARGET: usize = 4096;

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

/// The recorded state of one path. Fields are private; construct through the
/// validating constructors so the invariants below always hold:
///
/// * `mode <= 0o7777`
/// * `File`/`TooLarge`/`Sensitive`: `id` is a 32-byte digest
/// * `Symlink`: `id` is a non-empty target (at most [`MAX_LINK_TARGET`] bytes) and `size == id.len()`
/// * `Dir`: `size == 0`, no id
/// * `Special`/`Unreadable`: no id
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    kind: Kind,
    mode: u32,
    size: u64,
    mtime_ns: i64,
    ctime_ns: i64,
    id: Vec<u8>,
}

impl Entry {
    pub fn new(
        kind: Kind,
        mode: u32,
        size: u64,
        mtime_ns: i64,
        ctime_ns: i64,
        id: Vec<u8>,
    ) -> DomainResult<Entry> {
        let bad =
            |why: &str| DomainError::Invalid(format!("invalid {} entry: {why}", kind.as_str()));
        if mode > 0o7777 {
            return Err(bad("mode out of range"));
        }
        if kind.id_is_digest() {
            if id.len() != 32 {
                return Err(bad("id is not a 32-byte digest"));
            }
        } else if kind == Kind::Symlink {
            if id.is_empty() {
                return Err(bad("symlink without target"));
            }
            if id.len() > MAX_LINK_TARGET {
                return Err(bad("symlink target too long"));
            }
            if size != id.len() as u64 {
                return Err(bad("symlink size must equal target length"));
            }
        } else if !id.is_empty() {
            return Err(bad("unexpected id"));
        }
        if kind == Kind::Dir && size != 0 {
            return Err(bad("directory with a size"));
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

    pub fn symlink(target: Vec<u8>, mtime_ns: i64, ctime_ns: i64) -> DomainResult<Entry> {
        let size = target.len() as u64;
        Entry::new(Kind::Symlink, 0o777, size, mtime_ns, ctime_ns, target)
    }

    /// A regular file, a too-large file or a sensitive file: `id` is the digest.
    pub fn hashed(
        kind: Kind,
        digest: &Digest,
        mode: u32,
        size: u64,
        mtime_ns: i64,
        ctime_ns: i64,
    ) -> DomainResult<Entry> {
        if !kind.id_is_digest() {
            return Err(DomainError::Invalid(format!(
                "{} entries carry no digest",
                kind.as_str()
            )));
        }
        Entry::new(kind, mode, size, mtime_ns, ctime_ns, digest.to_vec())
    }

    /// FIFO, socket or device node.
    pub fn special(mode: u32, mtime_ns: i64, ctime_ns: i64) -> Entry {
        Entry {
            kind: Kind::Special,
            mode: mode & 0o7777,
            size: 0,
            mtime_ns,
            ctime_ns,
            id: Vec::new(),
        }
    }

    /// An object that could not be read.
    pub fn unreadable(mode: u32, size: u64, mtime_ns: i64, ctime_ns: i64) -> Entry {
        Entry {
            kind: Kind::Unreadable,
            mode: mode & 0o7777,
            size,
            mtime_ns,
            ctime_ns,
            id: Vec::new(),
        }
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }
    pub fn mode(&self) -> u32 {
        self.mode
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn mtime_ns(&self) -> i64 {
        self.mtime_ns
    }
    pub fn ctime_ns(&self) -> i64 {
        self.ctime_ns
    }
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// Same entry with different permission bits (symlink modes stay as recorded).
    pub fn with_mode(&self, mode: u32) -> Entry {
        Entry {
            mode: mode & 0o7777,
            ..self.clone()
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

    /// Canonical text form.
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

    pub fn decode(s: &str) -> DomainResult<Entry> {
        let bad = |why: &str| DomainError::Invalid(format!("bad entry {s:?}: {why}"));
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
        let id = if kind.id_is_digest() {
            digest_from_hex(id_s)
                .ok_or_else(|| bad("id is not a 64-char hex digest"))?
                .to_vec()
        } else if id_s == "-" {
            Vec::new()
        } else {
            pct_decode(id_s).ok_or_else(|| bad("id encoding"))?
        };
        Entry::new(kind, mode, size, mtime_ns, ctime_ns, id)
    }
}

#[cfg(test)]
mod tests;
