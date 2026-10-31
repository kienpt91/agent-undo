use super::*;
use crate::hash::sha256;

fn p(s: &str) -> RelPath {
    RelPath::new(s.as_bytes()).unwrap()
}

fn f(content: &[u8], mode: u32) -> Entry {
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

fn collect_merge(prev: Vec<(RelPath, Entry)>, new: Vec<(RelPath, Entry)>) -> Vec<Change> {
    let mut m = Merger::new(Some(VecSource::new(prev)));
    let mut out = Vec::new();
    let mut new = new;
    new.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, e) in &new {
        m.push(path, e, &mut |c| {
            out.push(c);
            Ok(())
        })
        .unwrap();
    }
    m.finish(&mut |c| {
        out.push(c);
        Ok(())
    })
    .unwrap();
    out
}

#[test]
fn classify_cases() {
    let a = f(b"x", 0o644);
    let b = f(b"y", 0o644);
    let c = a.with_mode(0o755);
    assert_eq!(classify(None, None), None);
    assert_eq!(classify(None, Some(&a)), Some(ChangeKind::Created));
    assert_eq!(classify(Some(&a), None), Some(ChangeKind::Deleted));
    assert_eq!(classify(Some(&a), Some(&b)), Some(ChangeKind::Modified));
    assert_eq!(classify(Some(&a), Some(&c)), Some(ChangeKind::ModeChanged));
    assert_eq!(classify(Some(&a), Some(&a)), None);
}

#[test]
fn change_new_returns_none_for_no_change() {
    let a = f(b"x", 0o644);
    assert!(Change::new(p("a"), Some(a.clone()), Some(a)).is_none());
}

#[test]
fn change_round_trip_with_hostile_path() {
    let a = f(b"x", 0o644);
    let path = RelPath::new(b"dir/we ird\tna\nme\x1b[31m\xff".to_vec()).unwrap();
    let c = Change::new(path.clone(), Some(a), None).unwrap();
    let line = c.encode();
    assert!(!line.contains('\n'));
    let back = Change::decode(&line).unwrap();
    assert_eq!(back, c);
    assert_eq!(back.path(), &path);
}

#[test]
fn change_decode_rejects_traversal_and_mismatch() {
    let a = f(b"x", 0o644).encode();
    assert!(Change::decode(&format!("deleted\t../etc/passwd\t{a}\t-")).is_err());
    assert!(Change::decode(&format!("deleted\t/abs\t{a}\t-")).is_err());
    assert!(Change::decode(&format!("created\ta\t{a}\t-")).is_err());
    assert!(Change::decode("deleted\ta").is_err());
    assert!(Change::decode(&format!("deleted\ta\t{a}\t-\textra")).is_err());
    assert!(Change::decode("bogus\ta\t-\t-").is_err());
}

#[test]
fn fingerprint_is_order_independent_and_sensitive_to_content() {
    let a = Change::new(p("a"), None, Some(f(b"1", 0o644))).unwrap();
    let b = Change::new(p("b"), None, Some(f(b"2", 0o644))).unwrap();
    let b2 = Change::new(p("b"), None, Some(f(b"3", 0o644))).unwrap();
    let ab = fingerprint_step(fingerprint_step(0, &a), &b);
    let ba = fingerprint_step(fingerprint_step(0, &b), &a);
    assert_eq!(ab, ba);
    assert_ne!(ab, fingerprint_step(fingerprint_step(0, &a), &b2));
    assert_ne!(ab, fingerprint_step(0, &a));
}

#[test]
fn boxed_sources_forward() {
    let mut s: Box<dyn EntrySource<Error = std::convert::Infallible>> =
        Box::new(VecSource::new(vec![(p("a"), f(b"1", 0o644))]));
    assert!(s.next_entry().unwrap().is_some());
    assert!(s.next_entry().unwrap().is_none());
}

#[test]
fn counts_total_and_add() {
    let mut c = Counts::default();
    for k in [
        ChangeKind::Created,
        ChangeKind::Created,
        ChangeKind::Deleted,
        ChangeKind::Modified,
        ChangeKind::ModeChanged,
    ] {
        c.add(k);
    }
    assert_eq!(
        (c.created, c.deleted, c.modified, c.mode_changed),
        (2, 1, 1, 1)
    );
    assert_eq!(c.total(), 5);
}

#[test]
fn merge_detects_created_modified_deleted_and_mode() {
    let prev = vec![
        (p("keep"), f(b"k", 0o644)),
        (p("mod"), f(b"1", 0o644)),
        (p("gone"), f(b"g", 0o644)),
        (p("mode"), f(b"m", 0o644)),
    ];
    let new = vec![
        (p("keep"), f(b"k", 0o644)),
        (p("mod"), f(b"2", 0o644)),
        (p("mode"), f(b"m", 0o755)),
        (p("new"), f(b"n", 0o644)),
    ];
    let got: Vec<(String, ChangeKind)> = collect_merge(prev, new)
        .iter()
        .map(|c| (c.path().display(), c.kind()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("gone".to_string(), ChangeKind::Deleted),
            ("mod".to_string(), ChangeKind::Modified),
            ("mode".to_string(), ChangeKind::ModeChanged),
            ("new".to_string(), ChangeKind::Created),
        ]
    );
}

#[test]
fn merge_ignores_timestamp_only_differences() {
    let a = f(b"x", 0o644);
    let touched = Entry::new(Kind::File, 0o644, 1, 999, 999, a.id().to_vec()).unwrap();
    assert!(collect_merge(vec![(p("a"), a)], vec![(p("a"), touched)]).is_empty());
}

#[test]
fn merge_with_no_previous_manifest_reports_everything_created() {
    let mut m: Merger<VecSource> = Merger::new(None);
    let mut out = Vec::new();
    m.push(&p("a"), &f(b"x", 0o644), &mut |c| {
        out.push(c);
        Ok(())
    })
    .unwrap();
    m.finish(&mut |_| Ok(())).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind(), ChangeKind::Created);
}

#[test]
fn merge_emits_deletions_of_whole_subtrees_in_order() {
    let prev = vec![
        (p("d"), Entry::dir(0o755, 0, 0)),
        (p("d/a"), f(b"a", 0o644)),
        (p("d/b"), f(b"b", 0o644)),
        (p("z"), f(b"z", 0o644)),
    ];
    let new = vec![(p("z"), f(b"z", 0o644))];
    let got: Vec<String> = collect_merge(prev, new)
        .iter()
        .map(|c| c.path().display())
        .collect();
    assert_eq!(got, vec!["d", "d/a", "d/b"]);
}

#[test]
fn lookup_serves_cache_and_reports_skipped_entries_as_deleted() {
    let mut m = Merger::new(Some(VecSource::new(vec![
        (p("a"), f(b"a", 0o644)),
        (p("c"), f(b"c", 0o644)),
    ])));
    let mut deleted = Vec::new();
    let hit = m
        .lookup(&p("c"), &mut |c| {
            deleted.push(c.path().display());
            Ok(())
        })
        .unwrap();
    assert!(hit.is_some());
    assert_eq!(deleted, vec!["a"]);
    assert!(m.lookup(&p("zz"), &mut |_| Ok(())).unwrap().is_none());
}

#[test]
fn next_under_carries_forward_a_directory() {
    let mut m = Merger::new(Some(VecSource::new(vec![
        (p("d"), Entry::dir(0o755, 0, 0)),
        (p("d/a"), f(b"a", 0o644)),
        (p("d/sub/b"), f(b"b", 0o644)),
        (p("dd"), f(b"x", 0o644)),
    ])));
    let mut changes = Vec::new();
    // The walker pushed `d` itself, then could not list it.
    m.push(&p("d"), &Entry::dir(0o755, 0, 0), &mut |c| {
        changes.push(c);
        Ok(())
    })
    .unwrap();
    let mut carried = Vec::new();
    while let Some((path, _)) = m.next_under(&p("d")).unwrap() {
        carried.push(path.display());
    }
    assert_eq!(carried, vec!["d/a", "d/sub/b"]);
    assert!(changes.is_empty());
    // `dd` is not below `d`.
    assert!(m.next_under(&p("d")).unwrap().is_none());
}

struct FailingSource {
    items: Vec<(RelPath, Entry)>,
    fail_after: bool,
}

impl EntrySource for FailingSource {
    type Error = &'static str;
    fn next_entry(&mut self) -> Result<Option<(RelPath, Entry)>, &'static str> {
        if self.items.is_empty() {
            return if self.fail_after {
                Err("source failed")
            } else {
                Ok(None)
            };
        }
        Ok(Some(self.items.remove(0)))
    }
}

#[test]
fn merger_propagates_source_errors() {
    let mut m = Merger::new(Some(FailingSource {
        items: vec![],
        fail_after: true,
    }));
    assert_eq!(m.finish(&mut |_| Ok(())), Err("source failed"));
}

#[test]
fn merger_propagates_callback_errors() {
    let mut m = Merger::new(Some(FailingSource {
        items: vec![(p("a"), f(b"1", 0o644))],
        fail_after: false,
    }));
    let r = m.push(&p("a"), &f(b"2", 0o644), &mut |_| Err("callback failed"));
    assert_eq!(r, Err("callback failed"));
}

#[test]
fn net_changes_keep_first_before_and_last_after() {
    let (a, b, c) = (f(b"a", 0o644), f(b"b", 0o644), f(b"c", 0o644));
    let mut n = NetChanges::new(10);
    n.add(Change::new(p("x"), Some(a.clone()), Some(b.clone())).unwrap())
        .unwrap();
    n.add(Change::new(p("x"), Some(b), Some(c.clone())).unwrap())
        .unwrap();
    n.add(Change::new(p("new"), None, Some(a.clone())).unwrap())
        .unwrap();
    let net = n.into_net();
    assert_eq!(net.len(), 2);
    let x = net.iter().find(|n| n.path == p("x")).unwrap();
    assert_eq!(x.before.as_ref(), Some(&a));
    assert_eq!(x.after.as_ref(), Some(&c));
}

#[test]
fn net_changes_drop_round_trips() {
    let a = f(b"a", 0o644);
    let b = f(b"b", 0o644);
    let mut n = NetChanges::new(10);
    n.add(Change::new(p("x"), Some(a.clone()), Some(b.clone())).unwrap())
        .unwrap();
    n.add(Change::new(p("x"), Some(b), Some(a)).unwrap())
        .unwrap();
    n.add(Change::new(p("y"), None, Some(f(b"y", 0o644))).unwrap())
        .unwrap();
    n.add(Change::new(p("y"), Some(f(b"y", 0o644)), None).unwrap())
        .unwrap();
    assert!(n.into_net().is_empty());
}

#[test]
fn net_changes_enforce_limit() {
    let mut n = NetChanges::new(2);
    for name in ["a", "b"] {
        n.add(Change::new(p(name), None, Some(f(b"x", 0o644))).unwrap())
            .unwrap();
    }
    let err = n
        .add(Change::new(p("c"), None, Some(f(b"x", 0o644))).unwrap())
        .unwrap_err();
    assert!(matches!(err, DomainError::Limit(_)));
    // existing paths can still be updated at the limit
    n.add(Change::new(p("a"), Some(f(b"x", 0o644)), None).unwrap())
        .unwrap();
}

#[test]
fn renames_pair_identical_content_one_to_one() {
    let content = f(b"same content", 0o644);
    let changes = vec![
        Change::new(p("new1"), None, Some(content.clone())).unwrap(),
        Change::new(p("new2"), None, Some(content.clone())).unwrap(),
        Change::new(p("old"), Some(content.clone()), None).unwrap(),
        Change::new(p("other"), Some(f(b"zzz", 0o644)), None).unwrap(),
    ];
    let r = detect_renames(&changes);
    assert_eq!(
        r,
        vec![Rename {
            from: p("old"),
            to: p("new1")
        }]
    );
}

#[test]
fn renames_ignore_empty_files_and_non_regular_entries() {
    let empty = f(b"", 0o644);
    let link = Entry::symlink(b"t".to_vec(), 0, 0).unwrap();
    let changes = vec![
        Change::new(p("a"), Some(empty.clone()), None).unwrap(),
        Change::new(p("b"), None, Some(empty)).unwrap(),
        Change::new(p("c"), Some(link.clone()), None).unwrap(),
        Change::new(p("d"), None, Some(link)).unwrap(),
    ];
    assert!(detect_renames(&changes).is_empty());
}
