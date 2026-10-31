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

impl<T: EntrySource + ?Sized> EntrySource for Box<T> {
    type Error = T::Error;
    fn next_entry(&mut self) -> Result<Option<(RelPath, Entry)>, Self::Error> {
        (**self).next_entry()
    }
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

/// Order-independent fingerprint accumulator over a pending change set: two
/// scans with the same changes (same paths, kinds and new states) produce the
/// same value whatever order the changes arrive in.
pub fn fingerprint_step(acc: u64, c: &Change) -> u64 {
    let mut h = crate::hash::Sha256::new();
    h.update(c.path().as_bytes());
    h.update(c.kind().as_str().as_bytes());
    if let Some(a) = c.after() {
        h.update(a.encode().as_bytes());
    }
    let d = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(d.get(..8).unwrap_or(&[0; 8]));
    acc.wrapping_add(u64::from_le_bytes(b))
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
mod tests;
