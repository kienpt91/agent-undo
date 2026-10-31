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
mod tests {
    use super::*;
    use crate::hash::sha256;

    pub(crate) fn file_entry(content: &[u8], mode: u32) -> Entry {
        Entry::hashed(
            Kind::File,
            &sha256(content),
            mode,
            content.len() as u64,
            10,
            20,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_all_kinds() {
        let entries = [
            file_entry(b"x", 0o644),
            Entry::hashed(Kind::TooLarge, &sha256(b"big"), 0o600, 99, 0, 0).unwrap(),
            Entry::hashed(Kind::Sensitive, &sha256(b"s"), 0o600, 1, 0, 0).unwrap(),
            Entry::symlink(b"../a b,c\n".to_vec(), -5, 0).unwrap(),
            Entry::dir(0o755, 1, 2),
            Entry::special(0o600, 0, 0),
            Entry::unreadable(0, 7, 0, 0),
        ];
        for e in entries {
            let enc = e.encode();
            assert!(!enc.contains('\n') && !enc.contains('\t') && !enc.contains(' '));
            assert_eq!(Entry::decode(&enc).unwrap(), e, "{enc}");
        }
    }

    #[test]
    fn constructor_rejects_every_invariant_violation() {
        let d = sha256(b"x").to_vec();
        assert!(
            Entry::new(Kind::File, 0o10000, 1, 0, 0, d.clone()).is_err(),
            "mode range"
        );
        assert!(
            Entry::new(Kind::File, 0o644, 1, 0, 0, vec![1; 31]).is_err(),
            "short digest"
        );
        assert!(Entry::new(Kind::TooLarge, 0o644, 1, 0, 0, vec![]).is_err());
        assert!(Entry::new(Kind::Sensitive, 0o644, 1, 0, 0, vec![1; 33]).is_err());
        assert!(
            Entry::new(Kind::Symlink, 0o777, 0, 0, 0, vec![]).is_err(),
            "empty target"
        );
        assert!(
            Entry::new(Kind::Symlink, 0o777, 3, 0, 0, b"ab".to_vec()).is_err(),
            "size != target len"
        );
        assert!(
            Entry::symlink(vec![b'a'; MAX_LINK_TARGET + 1], 0, 0).is_err(),
            "target too long"
        );
        assert!(
            Entry::new(Kind::Dir, 0o755, 5, 0, 0, vec![]).is_err(),
            "dir with size"
        );
        assert!(
            Entry::new(Kind::Dir, 0o755, 0, 0, 0, d.clone()).is_err(),
            "dir with id"
        );
        assert!(Entry::new(Kind::Special, 0o600, 0, 0, 0, d).is_err());
        assert!(Entry::hashed(Kind::Dir, &sha256(b"x"), 0, 0, 0, 0).is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
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
        let mut b = Entry::decode(&a.encode()).unwrap();
        b = Entry::new(b.kind, b.mode, b.size, 999, 999, b.id.clone()).unwrap();
        assert!(a.semantic_eq(&b));
        let c = b.with_mode(0o755);
        assert!(!a.semantic_eq(&c));
        assert!(a.same_content(&c));
    }

    #[test]
    fn symlink_mode_is_ignored_but_target_is_not() {
        let a = Entry::symlink(b"t".to_vec(), 0, 0).unwrap();
        assert!(a.semantic_eq(&a.with_mode(0o755)));
        assert!(!a.semantic_eq(&Entry::symlink(b"u".to_vec(), 0, 0).unwrap()));
    }

    #[test]
    fn accessors() {
        let e = file_entry(b"abc", 0o640);
        assert_eq!(e.kind(), Kind::File);
        assert_eq!(e.mode(), 0o640);
        assert_eq!(e.size(), 3);
        assert_eq!(e.mtime_ns(), 10);
        assert_eq!(e.ctime_ns(), 20);
        assert_eq!(e.blob(), Some(sha256(b"abc")));
        assert!(e.target().is_none());
        let t = Entry::hashed(Kind::TooLarge, &sha256(b"abc"), 0o640, 3, 0, 0).unwrap();
        assert_eq!(t.blob(), None, "only regular stored files have a blob");
        assert!(t.digest().is_some());
        let l = Entry::symlink(b"x".to_vec(), 0, 0).unwrap();
        assert_eq!(l.target(), Some(&b"x"[..]));
        assert!(l.digest().is_none());
    }

    #[test]
    fn kind_names_round_trip() {
        for k in [
            Kind::File,
            Kind::TooLarge,
            Kind::Sensitive,
            Kind::Symlink,
            Kind::Dir,
            Kind::Special,
            Kind::Unreadable,
        ] {
            assert_eq!(Kind::parse(k.as_str()), Some(k));
        }
        assert_eq!(Kind::parse("nope"), None);
    }
}
