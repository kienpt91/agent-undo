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
mod tests {
    use super::*;
    use crate::hash::sha256;

    fn file(size: u64, m: i64, c: i64) -> Entry {
        Entry::hashed(Kind::File, &sha256(b"x"), 0o644, size, m, c).unwrap()
    }

    #[test]
    fn sensitivity_beats_size() {
        assert_eq!(classify_file(true, false, 1, 100), FileClass::Sensitive);
        assert_eq!(classify_file(false, true, 1, 100), FileClass::Sensitive);
        assert_eq!(classify_file(true, false, 1_000, 100), FileClass::Sensitive);
        assert_eq!(classify_file(false, false, 101, 100), FileClass::TooLarge);
        assert_eq!(classify_file(false, false, 100, 100), FileClass::Storable);
        assert_eq!(classify_file(false, false, 0, 0), FileClass::Storable);
    }

    #[test]
    fn cache_requires_identical_stat_and_old_enough_timestamps() {
        let c = file(10, 100, 200);
        assert!(cache_usable(&c, 10, 100, 200, 1000));
        assert!(!cache_usable(&c, 11, 100, 200, 1000), "size differs");
        assert!(!cache_usable(&c, 10, 101, 200, 1000), "mtime differs");
        assert!(!cache_usable(&c, 10, 100, 201, 1000), "ctime differs");
        assert!(
            !cache_usable(&c, 10, 100, 200, 200),
            "ctime not older than the cutoff (racy)"
        );
        assert!(
            !cache_usable(&c, 10, 100, 200, 100),
            "mtime not older than the cutoff"
        );
    }

    #[test]
    fn sensitive_id_is_keyed_deterministic_and_not_the_plain_hash() {
        let h = sha256(b"secret content");
        let id = sensitive_id(b"key-one", &h);
        assert_ne!(id, h);
        assert_eq!(id, sensitive_id(b"key-one", &h));
        assert_ne!(
            id,
            sensitive_id(b"key-two", &h),
            "different keys give different ids"
        );
        assert_ne!(id, sensitive_id(b"key-one", &sha256(b"other")));
    }

    #[test]
    fn cache_ignores_non_file_entries() {
        let d = Entry::dir(0o755, 1, 1);
        assert!(!cache_usable(&d, 0, 1, 1, 1000));
        let l = Entry::symlink(b"t".to_vec(), 1, 1).unwrap();
        assert!(!cache_usable(&l, 1, 1, 1, 1000));
        let big = Entry::hashed(Kind::TooLarge, &sha256(b"x"), 0o644, 10, 1, 1).unwrap();
        assert!(cache_usable(&big, 10, 1, 1, 1000));
    }
}
