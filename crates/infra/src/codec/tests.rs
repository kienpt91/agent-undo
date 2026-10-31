use super::*;
use agent_undo_domain::entry::Kind;
use agent_undo_domain::hash::sha256;
use std::io::Cursor;

fn p(s: &str) -> RelPath {
    RelPath::new(s.as_bytes()).unwrap()
}

fn file_entry(content: &[u8], mode: u32) -> Entry {
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
fn manifest_round_trip_and_hash_is_stable() {
    let mut w = ManifestWriter::new(Vec::new()).unwrap();
    w.write_entry(&p("a"), &Entry::dir(0o755, 1, 1)).unwrap();
    w.write_entry(&p("a/b"), &file_entry(b"1", 0o644)).unwrap();
    w.write_entry(&p("a-b"), &file_entry(b"2", 0o600)).unwrap();
    let (bytes, digest, count) = w.finish().unwrap();
    assert_eq!(count, 3);
    assert_eq!(digest, sha256(&bytes));
    let mut r = ManifestReader::new(Cursor::new(bytes)).unwrap();
    let mut paths = Vec::new();
    while let Some((path, _)) = r.next_entry().unwrap() {
        paths.push(path.display());
    }
    assert_eq!(paths, vec!["a", "a/b", "a-b"]);
    assert_eq!(r.count(), 3);
}

#[test]
fn manifest_writer_rejects_out_of_order() {
    let mut w = ManifestWriter::new(Vec::new()).unwrap();
    w.write_entry(&p("b"), &Entry::dir(0o755, 1, 1)).unwrap();
    assert!(w.write_entry(&p("a"), &Entry::dir(0o755, 1, 1)).is_err());
    assert!(w.write_entry(&p("b"), &Entry::dir(0o755, 1, 1)).is_err());
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
fn manifest_reader_rejects_traversal_paths_and_garbage() {
    let e = Entry::dir(0o755, 1, 1).encode();
    for line in [
        format!("..%2Fx\t{e}"),
        format!("a/../b\t{e}"),
        format!("/abs\t{e}"),
        format!("a//b\t{e}"),
        format!("../x\t{e}"),
        "no-separator".to_string(),
        "a\tgarbage".to_string(),
        "%zz\tdir,755,0,1,1,-".to_string(),
    ] {
        let text = format!("{MANIFEST_HEADER}\n{line}\n");
        let mut r = ManifestReader::new(Cursor::new(text.into_bytes())).unwrap();
        assert!(r.next_entry().is_err(), "{line}");
    }
}

#[test]
fn manifest_reader_rejects_non_utf8() {
    let mut bytes = format!("{MANIFEST_HEADER}\n").into_bytes();
    bytes.extend_from_slice(b"a\t\xff\n");
    let mut r = ManifestReader::new(Cursor::new(bytes)).unwrap();
    assert!(matches!(r.next_entry(), Err(Error::Format(_))));
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
    w.write_change(&Change::new(p("f"), Some(a.clone()), Some(b)).unwrap())
        .unwrap();
    w.write_change(&Change::new(p("g"), None, Some(a)).unwrap())
        .unwrap();
    let (bytes, digest, count) = w.finish().unwrap();
    assert_eq!(count, 2);
    assert_eq!(digest, sha256(&bytes));
    let mut r = ChangesReader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(r.next_change().unwrap().unwrap().path(), &p("f"));
    assert_eq!(r.next_change().unwrap().unwrap().path(), &p("g"));
    assert!(r.next_change().unwrap().is_none());
}

#[test]
fn changes_reader_rejects_bad_header_and_records() {
    assert!(ChangesReader::new(Cursor::new(b"x\n".to_vec())).is_err());
    assert!(ChangesReader::new(Cursor::new(Vec::new())).is_err());
    let text = format!("{CHANGES_HEADER}\ngarbage\n");
    let mut r = ChangesReader::new(Cursor::new(text.into_bytes())).unwrap();
    assert!(r.next_change().is_err());
}
