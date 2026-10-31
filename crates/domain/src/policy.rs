//! Snapshot policy rules that are independent of how files are read.

use crate::entry::{Entry, Kind};
use crate::error::{DomainError, DomainResult};
use crate::hash::{Digest, digest_from_hex, hmac_sha256, to_hex};
use std::collections::HashSet;

/// How a regular file is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    /// Sensitive: size and keyed hash-of-hash only, never stored.
    Sensitive,
    /// Above the size cap: hash only, cannot be restored.
    TooLarge,
    /// Content is stored as a blob.
    Storable,
}

/// Classifies a regular file. Sensitivity always wins over the size cap, so a
/// huge secret file is still treated as a secret. A file is sensitive when
///
/// * its name says so (`name_sensitive`),
/// * its content matches a detector (`content_flagged`), or
/// * its content is byte-for-byte the content of a file that was sensitive
///   before (`known_content`): copying or renaming a secret file to an innocent
///   name does not make it storable.
pub fn classify_file(
    name_sensitive: bool,
    content_flagged: bool,
    known_content: bool,
    size: u64,
    max_file_size: u64,
) -> FileClass {
    if name_sensitive || content_flagged || known_content {
        FileClass::Sensitive
    } else if size > max_file_size {
        FileClass::TooLarge
    } else {
        FileClass::Storable
    }
}

/// Outcome of [`SensitiveIds::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    Added,
    Known,
    /// The cap was reached; the id was not recorded.
    Full,
}

/// The set of keyed ids ([`sensitive_id`]) of every content that was ever
/// classified as sensitive in this project. Only ids are kept, never content or
/// plain hashes. Bounded: at `cap` ids new ones are refused (and reported) rather
/// than growing without limit.
#[derive(Debug, Clone)]
pub struct SensitiveIds {
    ids: HashSet<Digest>,
    cap: usize,
}

impl SensitiveIds {
    pub fn new(cap: usize) -> SensitiveIds {
        SensitiveIds {
            ids: HashSet::new(),
            cap,
        }
    }

    pub fn contains(&self, id: &Digest) -> bool {
        self.ids.contains(id)
    }

    pub fn insert(&mut self, id: Digest) -> Insert {
        if self.ids.contains(&id) {
            Insert::Known
        } else if self.ids.len() >= self.cap {
            Insert::Full
        } else {
            self.ids.insert(id);
            Insert::Added
        }
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// One line (`<64 hex>\n`) for appending to the persisted list.
    pub fn encode_one(id: &Digest) -> String {
        format!("{}\n", to_hex(id))
    }

    /// All ids, one per line, in no particular order.
    pub fn encode_all(&self) -> String {
        self.ids.iter().map(SensitiveIds::encode_one).collect()
    }

    /// Parses the persisted list; more than `cap` ids or any malformed line is an error.
    pub fn decode(text: &str, cap: usize) -> DomainResult<SensitiveIds> {
        let mut out = SensitiveIds::new(cap);
        for line in text.lines().filter(|l| !l.is_empty()) {
            let id = digest_from_hex(line)
                .ok_or_else(|| DomainError::Invalid("malformed sensitive id list".into()))?;
            if out.insert(id) == Insert::Full {
                return Err(DomainError::Invalid(
                    "sensitive id list is larger than its cap".into(),
                ));
            }
        }
        Ok(out)
    }
}

/// Keyed "hash of hash" recorded for sensitive files: HMAC-SHA-256 of the
/// content hash under the store key. Without the key the manifest value cannot be
/// used to brute-force the file content, yet two snapshots of the same content
/// still compare equal.
pub fn sensitive_id(key: &[u8], content_hash: &Digest) -> Digest {
    let mut msg = Vec::with_capacity(5 + 32);
    msg.extend_from_slice(b"sens\0");
    msg.extend_from_slice(content_hash);
    hmac_sha256(key, &msg)
}

/// Whether a previously recorded entry may stand in for re-reading the file.
///
/// The cached entry must describe a file with the same size, mtime and ctime,
/// and both timestamps must be older than `cutoff_ns` (the previous snapshot's
/// start time minus a safety margin): a file modified close to the snapshot may
/// have changed again within the same timestamp tick (the "racy" case).
pub fn cache_usable(
    cached: &Entry,
    size: u64,
    mtime_ns: i64,
    ctime_ns: i64,
    cutoff_ns: i64,
) -> bool {
    matches!(cached.kind(), Kind::File | Kind::TooLarge | Kind::Sensitive)
        && cached.size() == size
        && cached.mtime_ns() == mtime_ns
        && cached.ctime_ns() == ctime_ns
        && mtime_ns.max(ctime_ns) < cutoff_ns
}

#[cfg(test)]
mod tests;
