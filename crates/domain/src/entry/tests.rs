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
