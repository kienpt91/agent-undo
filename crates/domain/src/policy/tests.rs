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
