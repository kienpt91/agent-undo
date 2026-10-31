//! Snapshot policy rules that are independent of how files are read.

use crate::entry::{Entry, Kind};
use crate::hash::{Digest, hmac_sha256};

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

/// Classifies a regular file. Sensitivity (by name or by content) always wins
/// over the size cap, so a huge secret file is still treated as a secret.
pub fn classify_file(
    name_sensitive: bool,
    content_flagged: bool,
    size: u64,
    max_file_size: u64,
) -> FileClass {
    if name_sensitive || content_flagged {
        FileClass::Sensitive
    } else if size > max_file_size {
        FileClass::TooLarge
    } else {
        FileClass::Storable
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
