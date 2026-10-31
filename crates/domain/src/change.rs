//! Changes between two states of the project: classification, the streaming
//! merge of a new walk against the previous manifest, composition of several
//! checkpoints into net changes, and rename detection.

use crate::entry::{Entry, Kind};
use crate::error::{DomainError, DomainResult};
use crate::esc::{pct_decode, pct_encode};
use crate::hash::Digest;
use crate::path::RelPath;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

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

/// Counts of changes by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub created: u64,
    pub modified: u64,
    pub deleted: u64,
    pub mode_changed: u64,
}

impl Counts {
    pub fn total(&self) -> u64 {
        self.created + self.modified + self.deleted + self.mode_changed
    }

    pub fn add(&mut self, kind: ChangeKind) {
        match kind {
            ChangeKind::Created => self.created += 1,
            ChangeKind::Modified => self.modified += 1,
            ChangeKind::Deleted => self.deleted += 1,
            ChangeKind::ModeChanged => self.mode_changed += 1,
        }
    }
}

/// One path whose state differs between two points in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    kind: ChangeKind,
    path: RelPath,
    before: Option<Entry>,
    after: Option<Entry>,
}

fn encode_opt(e: &Option<Entry>) -> String {
    e.as_ref().map_or_else(|| "-".to_string(), Entry::encode)
}

fn decode_opt(s: &str) -> DomainResult<Option<Entry>> {
    if s == "-" {
        Ok(None)
    } else {
        Entry::decode(s).map(Some)
    }
}

impl Change {
    /// `None` when `before` and `after` are semantically equal (no change).
    pub fn new(path: RelPath, before: Option<Entry>, after: Option<Entry>) -> Option<Change> {
        let kind = classify(before.as_ref(), after.as_ref())?;
        Some(Change {
            kind,
            path,
            before,
            after,
        })
    }

    pub fn kind(&self) -> ChangeKind {
        self.kind
    }
    pub fn path(&self) -> &RelPath {
        &self.path
    }
    pub fn before(&self) -> Option<&Entry> {
        self.before.as_ref()
    }
    pub fn after(&self) -> Option<&Entry> {
        self.after.as_ref()
    }
    pub fn into_parts(self) -> (RelPath, Option<Entry>, Option<Entry>) {
        (self.path, self.before, self.after)
    }

    /// Canonical text form: `kind\tpath\tbefore\tafter`.
    pub fn encode(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.kind.as_str(),
            pct_encode(self.path.as_bytes()),
            encode_opt(&self.before),
            encode_opt(&self.after)
        )
    }

    pub fn decode(line: &str) -> DomainResult<Change> {
        let bad = |why: &str| DomainError::Invalid(format!("bad change record: {why}"));
        let mut it = line.split('\t');
        let kind = ChangeKind::parse(it.next().ok_or_else(|| bad("missing type"))?)
            .ok_or_else(|| bad("unknown type"))?;
        let path = pct_decode(it.next().ok_or_else(|| bad("missing path"))?)
            .ok_or_else(|| bad("path encoding"))?;
        let path = RelPath::new(path)?;
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

// ------------------------------------------------------------------- merge

/// A sorted stream of manifest entries (strictly increasing [`RelPath`] order).
pub trait EntrySource {
    type Error;
    fn next_entry(&mut self) -> Result<Option<(RelPath, Entry)>, Self::Error>;
}

/// In-memory entry source (already sorted).
pub struct VecSource {
    items: std::collections::VecDeque<(RelPath, Entry)>,
}

impl VecSource {
    /// Sorts `items` by path.
    pub fn new(mut items: Vec<(RelPath, Entry)>) -> VecSource {
        items.sort_by(|a, b| a.0.cmp(&b.0));
        VecSource {
            items: items.into(),
        }
    }
}

impl EntrySource for VecSource {
    type Error = std::convert::Infallible;
    fn next_entry(&mut self) -> Result<Option<(RelPath, Entry)>, Self::Error> {
        Ok(self.items.pop_front())
    }
}

/// Streaming merge of a new, sorted walk against the previous manifest.
///
/// The walker asks [`Merger::lookup`] for the previous entry of each path (the
/// stat cache), reports each new entry with [`Merger::push`], and calls
/// [`Merger::finish`] at the end. Changes are emitted through a callback, in path
/// order, so memory use does not depend on the number of changes.
pub struct Merger<S: EntrySource> {
    source: Option<S>,
    head: Option<(RelPath, Entry)>,
    done: bool,
}

type OnChange<'a, E> = &'a mut dyn FnMut(Change) -> Result<(), E>;

impl<S: EntrySource> Merger<S> {
    pub fn new(source: Option<S>) -> Merger<S> {
        let done = source.is_none();
        Merger {
            source,
            head: None,
            done,
        }
    }

    fn fill(&mut self) -> Result<(), S::Error> {
        if self.head.is_none()
            && !self.done
            && let Some(r) = self.source.as_mut()
        {
            match r.next_entry()? {
                Some(h) => self.head = Some(h),
                None => self.done = true,
            }
        }
        Ok(())
    }

    /// Emits `Deleted` for previous entries ordered before `path`.
    fn advance_to(
        &mut self,
        path: &RelPath,
        on_change: OnChange<'_, S::Error>,
    ) -> Result<(), S::Error> {
        loop {
            self.fill()?;
            let before = matches!(&self.head, Some((hp, _)) if hp.cmp(path) == Ordering::Less);
            if !before {
                return Ok(());
            }
            if let Some((hp, he)) = self.head.take()
                && let Some(c) = Change::new(hp, Some(he), None)
            {
                on_change(c)?;
            }
        }
    }

    /// Previous entry for `path`, if any.
    pub fn lookup(
        &mut self,
        path: &RelPath,
        on_change: OnChange<'_, S::Error>,
    ) -> Result<Option<Entry>, S::Error> {
        self.advance_to(path, on_change)?;
        Ok(match &self.head {
            Some((hp, he)) if hp == path => Some(he.clone()),
            _ => None,
        })
    }

    /// Reports the new state of `path` (paths must be pushed in increasing order).
    pub fn push(
        &mut self,
        path: &RelPath,
        new: &Entry,
        on_change: OnChange<'_, S::Error>,
    ) -> Result<(), S::Error> {
        self.advance_to(path, on_change)?;
        let old = match &self.head {
            Some((hp, _)) if hp == path => self.head.take().map(|(_, e)| e),
            _ => None,
        };
        if let Some(c) = Change::new(path.clone(), old, Some(new.clone())) {
            on_change(c)?;
        }
        Ok(())
    }

    /// Takes the next previous entry located below directory `dir` (used when a
    /// directory could not be listed and its old entries are carried forward).
    pub fn next_under(&mut self, dir: &RelPath) -> Result<Option<(RelPath, Entry)>, S::Error> {
        self.fill()?;
        let under = matches!(&self.head, Some((hp, _)) if hp.is_below(dir));
        Ok(if under { self.head.take() } else { None })
    }

    /// Emits `Deleted` for every remaining previous entry.
    pub fn finish(&mut self, on_change: OnChange<'_, S::Error>) -> Result<(), S::Error> {
        loop {
            self.fill()?;
            match self.head.take() {
                Some((hp, he)) => {
                    if let Some(c) = Change::new(hp, Some(he), None) {
                        on_change(c)?;
                    }
                }
                None => return Ok(()),
            }
        }
    }
}

// ------------------------------------------------------------ composition

/// Net effect on one path across several checkpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetChange {
    pub path: RelPath,
    pub before: Option<Entry>,
    pub after: Option<Entry>,
}

/// Accumulates changes from consecutive checkpoints: the first `before` and the
/// last `after` per path win. Bounded by `limit` distinct paths.
#[derive(Debug)]
pub struct NetChanges {
    map: BTreeMap<RelPath, (Option<Entry>, Option<Entry>)>,
    limit: usize,
}

impl NetChanges {
    pub fn new(limit: usize) -> NetChanges {
        NetChanges {
            map: BTreeMap::new(),
            limit,
        }
    }

    pub fn add(&mut self, c: Change) -> DomainResult<()> {
        let (path, before, after) = c.into_parts();
        match self.map.get_mut(&path) {
            Some(slot) => slot.1 = after,
            None => {
                if self.map.len() >= self.limit {
                    return Err(DomainError::Limit(format!(
                        "more than {} paths changed; refusing to build an in-memory plan",
                        self.limit
                    )));
                }
                self.map.insert(path, (before, after));
            }
        }
        Ok(())
    }

    /// Paths in order, omitting those whose net effect is nothing.
    pub fn into_net(self) -> Vec<NetChange> {
        self.map
            .into_iter()
            .filter(|(_, (b, a))| match (b, a) {
                (None, None) => false,
                (Some(x), Some(y)) => !x.semantic_eq(y),
                _ => true,
            })
            .map(|(path, (before, after))| NetChange {
                path,
                before,
                after,
            })
            .collect()
    }
}

// ---------------------------------------------------------------- renames

/// A deleted and a created path with identical content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rename {
    pub from: RelPath,
    pub to: RelPath,
}

/// Pairs deleted and created regular files with the same non-empty content, one
/// to one in path order.
pub fn detect_renames(changes: &[Change]) -> Vec<Rename> {
    let mut deleted: HashMap<Digest, Vec<&RelPath>> = HashMap::new();
    for c in changes.iter().filter(|c| c.kind() == ChangeKind::Deleted) {
        if let Some(e) = c.before()
            && e.kind() == Kind::File
            && e.size() > 0
            && let Some(d) = e.digest()
        {
            deleted.entry(d).or_default().push(c.path());
        }
    }
    for list in deleted.values_mut() {
        list.reverse(); // pop() yields the smallest path first
    }
    let mut out = Vec::new();
    for c in changes.iter().filter(|c| c.kind() == ChangeKind::Created) {
        if let Some(e) = c.after()
            && e.kind() == Kind::File
            && e.size() > 0
            && let Some(d) = e.digest()
            && let Some(from) = deleted.get_mut(&d).and_then(Vec::pop)
        {
            out.push(Rename {
                from: from.clone(),
                to: c.path().clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
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
}
