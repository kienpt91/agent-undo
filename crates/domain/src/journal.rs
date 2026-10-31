//! The `Journal` aggregate: the hash-chained history of checkpoints.
//!
//! Invariants protected here:
//!
//! * ids are contiguous from 1 and every record's `prev` is the hash of its
//!   predecessor (a tamper-evident chain);
//! * the first record is the baseline and no other record is;
//! * sessions never go backwards and start only through `new_session`;
//! * `pre-undo`, `undo` and `restore` records reference an earlier checkpoint,
//!   other kinds do not;
//! * the newest checkpoint is never pruned (it is the base of the next diff).
//!
//! The journal performs no IO and reads no clock: callers pass `time_ns`.

use crate::change::Counts;
use crate::error::{DomainError, DomainResult};
use crate::esc::{pct_decode, pct_encode};
use crate::hash::{Digest, digest_from_hex, sha256, to_hex};
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_LABEL_BYTES: usize = 200;
pub const MAX_COMMAND_BYTES: usize = 4096;
pub const GENESIS_PREV: Digest = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckpointId(u64);

impl CheckpointId {
    pub fn new(n: u64) -> DomainResult<CheckpointId> {
        if n == 0 {
            return Err(DomainError::Invalid("checkpoint numbers start at 1".into()));
        }
        Ok(CheckpointId(n))
    }

    pub fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> CheckpointId {
        CheckpointId(self.0 + 1)
    }
}

impl fmt::Display for CheckpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    pub fn new(n: u64) -> DomainResult<SessionId> {
        if n == 0 {
            return Err(DomainError::Invalid("session numbers start at 1".into()));
        }
        Ok(SessionId(n))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A short free-text label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label(Vec<u8>);

impl Label {
    pub fn new(bytes: impl Into<Vec<u8>>) -> DomainResult<Label> {
        let b = bytes.into();
        if b.len() > MAX_LABEL_BYTES {
            return Err(DomainError::Usage(format!(
                "label is {} bytes; the limit is {MAX_LABEL_BYTES}",
                b.len()
            )));
        }
        Ok(Label(b))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The command line of a `run` checkpoint, truncated to a bounded size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine(Vec<Vec<u8>>);

impl CommandLine {
    /// Keeps whole arguments while the total stays within [`MAX_COMMAND_BYTES`];
    /// a final `...[truncated]` argument marks the cut.
    pub fn bounded(args: &[Vec<u8>]) -> CommandLine {
        let mut out = Vec::new();
        let mut total = 0usize;
        for a in args {
            total = total.saturating_add(a.len() + 1);
            if total > MAX_COMMAND_BYTES {
                out.push(b"...[truncated]".to_vec());
                break;
            }
            out.push(a.clone());
        }
        CommandLine(out)
    }

    pub fn args(&self) -> &[Vec<u8>] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CkptKind {
    Baseline,
    Run,
    Manual,
    /// Changes made outside any recorded run, found by the snapshot before a run.
    External,
    Watch,
    /// Automatic snapshot taken before `undo`/`restore` modifies anything.
    PreUndo,
    Undo,
    Restore,
}

impl CkptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CkptKind::Baseline => "baseline",
            CkptKind::Run => "run",
            CkptKind::Manual => "manual",
            CkptKind::External => "external",
            CkptKind::Watch => "watch",
            CkptKind::PreUndo => "pre-undo",
            CkptKind::Undo => "undo",
            CkptKind::Restore => "restore",
        }
    }

    pub fn parse(s: &str) -> Option<CkptKind> {
        Some(match s {
            "baseline" => CkptKind::Baseline,
            "run" => CkptKind::Run,
            "manual" => CkptKind::Manual,
            "external" => CkptKind::External,
            "watch" => CkptKind::Watch,
            "pre-undo" => CkptKind::PreUndo,
            "undo" => CkptKind::Undo,
            "restore" => CkptKind::Restore,
            _ => return None,
        })
    }

    /// Kinds that must reference the checkpoint they relate to.
    pub fn needs_reference(self) -> bool {
        matches!(self, CkptKind::PreUndo | CkptKind::Undo | CkptKind::Restore)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitInfo {
    Code(i32),
    Signal(i32),
}

impl ExitInfo {
    fn encode(self) -> String {
        match self {
            ExitInfo::Code(c) => format!("exit:{c}"),
            ExitInfo::Signal(s) => format!("signal:{s}"),
        }
    }

    fn decode(s: &str) -> Option<Option<ExitInfo>> {
        if s == "-" {
            return Some(None);
        }
        let (k, v) = s.split_once(':')?;
        let n: i32 = v.parse().ok()?;
        match k {
            "exit" => Some(Some(ExitInfo::Code(n))),
            "signal" => Some(Some(ExitInfo::Signal(n))),
            _ => None,
        }
    }

    /// Conventional shell-style status.
    pub fn status_code(self) -> i32 {
        match self {
            ExitInfo::Code(c) => c,
            ExitInfo::Signal(s) => 128 + s,
        }
    }
}

/// One checkpoint record in the hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRecord {
    pub id: CheckpointId,
    pub session: SessionId,
    pub kind: CkptKind,
    pub time_ns: i64,
    pub exit: Option<ExitInfo>,
    pub label: Option<Label>,
    pub command: Option<CommandLine>,
    pub manifest: Digest,
    pub changes: Digest,
    pub counts: Counts,
    pub entries: u64,
    /// For `undo`/`restore`/`pre-undo`: the checkpoint this relates to.
    pub reference: Option<CheckpointId>,
    pub prev: Digest,
    pub hash: Digest,
}

fn enc_opt_bytes(b: Option<&[u8]>) -> String {
    match b {
        None => "-".to_string(),
        Some(b) => format!("={}", pct_encode(b)),
    }
}

fn dec_opt_bytes(s: &str) -> Option<Option<Vec<u8>>> {
    if s == "-" {
        return Some(None);
    }
    pct_decode(s.strip_prefix('=')?).map(Some)
}

impl CheckpointRecord {
    fn body(&self) -> String {
        let cmd = self.command.as_ref().map(|c| {
            c.args()
                .iter()
                .map(|a| pct_encode(a))
                .collect::<Vec<_>>()
                .join(" ")
        });
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.id.get(),
            self.session.get(),
            self.kind.as_str(),
            self.time_ns,
            self.exit.map_or_else(|| "-".to_string(), ExitInfo::encode),
            enc_opt_bytes(self.label.as_ref().map(Label::as_bytes)),
            enc_opt_bytes(cmd.as_deref().map(str::as_bytes)),
            to_hex(&self.manifest),
            to_hex(&self.changes),
            self.counts.created,
            self.counts.modified,
            self.counts.deleted,
            self.counts.mode_changed,
            self.entries,
            self.reference
                .map_or_else(|| "-".to_string(), |r| r.get().to_string()),
            to_hex(&self.prev),
        )
    }

    /// Chain hash over the record body (which includes `prev`).
    pub fn compute_hash(&self) -> Digest {
        sha256(self.body().as_bytes())
    }

    /// Canonical single-line text form including the hash.
    pub fn encode(&self) -> String {
        format!("{}\t{}", self.body(), to_hex(&self.hash))
    }

    pub fn decode(line: &str) -> DomainResult<CheckpointRecord> {
        let bad = |why: &str| DomainError::Invalid(format!("bad log record: {why}"));
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 17 {
            return Err(bad("wrong field count"));
        }
        let get = |i: usize| f.get(i).copied().unwrap_or("");
        let num =
            |i: usize, name: &str| -> DomainResult<u64> { get(i).parse().map_err(|_| bad(name)) };
        let command = match dec_opt_bytes(get(6)).ok_or_else(|| bad("command"))? {
            None => None,
            Some(joined) => {
                let s = String::from_utf8(joined).map_err(|_| bad("command text"))?;
                let mut args = Vec::new();
                for part in s.split(' ') {
                    args.push(pct_decode(part).ok_or_else(|| bad("command encoding"))?);
                }
                Some(CommandLine(args))
            }
        };
        let hex = |i: usize, name: &str| digest_from_hex(get(i)).ok_or_else(|| bad(name));
        let label = match dec_opt_bytes(get(5)).ok_or_else(|| bad("label"))? {
            None => None,
            Some(b) => Some(Label::new(b).map_err(|_| bad("label too long"))?),
        };
        Ok(CheckpointRecord {
            id: CheckpointId::new(num(0, "seq")?)?,
            session: SessionId::new(num(1, "session")?)?,
            kind: CkptKind::parse(get(2)).ok_or_else(|| bad("kind"))?,
            time_ns: get(3).parse().map_err(|_| bad("time"))?,
            exit: ExitInfo::decode(get(4)).ok_or_else(|| bad("exit"))?,
            label,
            command,
            manifest: hex(7, "manifest hash")?,
            changes: hex(8, "changes hash")?,
            counts: Counts {
                created: num(9, "created")?,
                modified: num(10, "modified")?,
                deleted: num(11, "deleted")?,
                mode_changed: num(12, "mode_changed")?,
            },
            entries: num(13, "entries")?,
            reference: match get(14) {
                "-" => None,
                s => Some(CheckpointId::new(s.parse().map_err(|_| bad("reference"))?)?),
            },
            prev: hex(15, "prev")?,
            hash: hex(16, "hash")?,
        })
    }
}

/// Everything needed to record a checkpoint; the journal adds id, session and chain.
#[derive(Debug, Clone)]
pub struct NewCheckpoint {
    pub kind: CkptKind,
    pub label: Option<Label>,
    pub command: Option<CommandLine>,
    pub exit: Option<ExitInfo>,
    pub new_session: bool,
    pub reference: Option<CheckpointId>,
    pub time_ns: i64,
    pub manifest: Digest,
    pub changes: Digest,
    pub counts: Counts,
    pub entries: u64,
}

impl NewCheckpoint {
    pub fn new(
        kind: CkptKind,
        time_ns: i64,
        manifest: Digest,
        changes: Digest,
        counts: Counts,
        entries: u64,
    ) -> NewCheckpoint {
        NewCheckpoint {
            kind,
            label: None,
            command: None,
            exit: None,
            new_session: false,
            reference: None,
            time_ns,
            manifest,
            changes,
            counts,
            entries,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainEvent {
    SessionStarted {
        session: SessionId,
    },
    CheckpointRecorded {
        id: CheckpointId,
        session: SessionId,
        kind: CkptKind,
        changes: u64,
    },
    CheckpointsPruned {
        ids: Vec<CheckpointId>,
    },
}

/// Which checkpoints a user wants to undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Checkpoint(CheckpointId),
    /// The newest checkpoint that recorded changes (not baseline/pre-undo).
    Last,
    /// A whole session (`None` = the current one).
    Session(Option<SessionId>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionPolicy {
    /// Keep the newest `n` checkpoints (`n >= 1`).
    KeepLast(usize),
    /// Drop checkpoints older than this many nanoseconds.
    OlderThan(i64),
}

impl RetentionPolicy {
    pub fn keep_last(n: usize) -> DomainResult<RetentionPolicy> {
        if n == 0 {
            return Err(DomainError::Usage("--keep must be at least 1".into()));
        }
        Ok(RetentionPolicy::KeepLast(n))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Journal {
    records: Vec<CheckpointRecord>,
    pruned: BTreeSet<u64>,
}

impl Journal {
    pub fn empty() -> Journal {
        Journal::default()
    }

    /// Rebuilds a journal from stored records, verifying every invariant.
    pub fn from_records(
        records: Vec<CheckpointRecord>,
        pruned: BTreeSet<u64>,
    ) -> DomainResult<Journal> {
        let mut prev = GENESIS_PREV;
        let mut last_session = 0u64;
        for (i, r) in records.iter().enumerate() {
            let expect = i as u64 + 1;
            if r.id.get() != expect {
                return Err(DomainError::Integrity(format!(
                    "log entry {expect}: sequence {} where {expect} was expected",
                    r.id.get()
                )));
            }
            if r.prev != prev {
                return Err(DomainError::Integrity(format!(
                    "log entry {expect}: hash chain broken (previous hash does not match)"
                )));
            }
            if r.compute_hash() != r.hash {
                return Err(DomainError::Integrity(format!(
                    "log entry {expect}: record hash mismatch (entry was modified)"
                )));
            }
            if (i == 0) != (r.kind == CkptKind::Baseline) {
                return Err(DomainError::Integrity(format!(
                    "log entry {expect}: the baseline must be the first record and only the first"
                )));
            }
            let s = r.session.get();
            if s < last_session || s > last_session + 1 || (i == 0 && s != 1) {
                return Err(DomainError::Integrity(format!(
                    "log entry {expect}: invalid session number {s}"
                )));
            }
            match (r.kind.needs_reference(), r.reference) {
                (true, None) => {
                    return Err(DomainError::Integrity(format!(
                        "log entry {expect}: missing reference"
                    )));
                }
                (false, Some(_)) => {
                    return Err(DomainError::Integrity(format!(
                        "log entry {expect}: unexpected reference"
                    )));
                }
                (true, Some(re)) if re.get() >= expect => {
                    return Err(DomainError::Integrity(format!(
                        "log entry {expect}: reference to a later checkpoint"
                    )));
                }
                _ => {}
            }
            prev = r.hash;
            last_session = s;
        }
        let head = records.len() as u64;
        if let Some(bad) = pruned.iter().find(|p| **p == 0 || **p >= head) {
            return Err(DomainError::Integrity(format!(
                "pruned list names checkpoint #{bad}, which is not prunable"
            )));
        }
        Ok(Journal { records, pruned })
    }

    pub fn records(&self) -> &[CheckpointRecord] {
        &self.records
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn head(&self) -> Option<&CheckpointRecord> {
        self.records.last()
    }

    pub fn find(&self, id: CheckpointId) -> DomainResult<&CheckpointRecord> {
        usize::try_from(id.get())
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| self.records.get(i))
            .ok_or_else(|| DomainError::Usage(format!("no checkpoint {id}")))
    }

    pub fn current_session(&self) -> Option<SessionId> {
        self.head().map(|h| h.session)
    }

    pub fn is_pruned(&self, id: CheckpointId) -> bool {
        self.pruned.contains(&id.get())
    }

    pub fn pruned(&self) -> &BTreeSet<u64> {
        &self.pruned
    }

    /// Appends a checkpoint, returning the sealed record and the events it caused.
    pub fn record(
        &mut self,
        new: NewCheckpoint,
    ) -> DomainResult<(CheckpointRecord, Vec<DomainEvent>)> {
        if new.time_ns < 0 {
            return Err(DomainError::Invalid(
                "checkpoint time must not be negative".into(),
            ));
        }
        let first = self.records.is_empty();
        if first != (new.kind == CkptKind::Baseline) {
            return Err(DomainError::Refused(if first {
                "the first checkpoint must be the baseline".into()
            } else {
                "a baseline already exists".into()
            }));
        }
        let id = self.head().map_or(CheckpointId(1), |h| h.id.next());
        match (new.kind.needs_reference(), new.reference) {
            (true, None) => {
                return Err(DomainError::Invalid(format!(
                    "a {} checkpoint must reference another checkpoint",
                    new.kind.as_str()
                )));
            }
            (false, Some(_)) => {
                return Err(DomainError::Invalid(format!(
                    "a {} checkpoint cannot carry a reference",
                    new.kind.as_str()
                )));
            }
            (true, Some(r)) => {
                self.find(r)?;
            }
            _ => {}
        }
        if first && new.new_session {
            return Err(DomainError::Invalid(
                "the baseline always opens session 1".into(),
            ));
        }
        let (session, started) = match self.head() {
            None => (SessionId(1), true),
            Some(h) if new.new_session => (SessionId(h.session.get() + 1), true),
            Some(h) => (h.session, false),
        };
        let mut rec = CheckpointRecord {
            id,
            session,
            kind: new.kind,
            time_ns: new.time_ns,
            exit: new.exit,
            label: new.label,
            command: new.command,
            manifest: new.manifest,
            changes: new.changes,
            counts: new.counts,
            entries: new.entries,
            reference: new.reference,
            prev: self.head().map_or(GENESIS_PREV, |h| h.hash),
            hash: [0; 32],
        };
        rec.hash = rec.compute_hash();
        let mut events = Vec::new();
        if started {
            events.push(DomainEvent::SessionStarted { session });
        }
        events.push(DomainEvent::CheckpointRecorded {
            id,
            session,
            kind: rec.kind,
            changes: rec.counts.total(),
        });
        self.records.push(rec.clone());
        Ok((rec, events))
    }

    /// Checkpoints that `policy` would remove (never the newest, never already pruned).
    pub fn prunable(&self, policy: RetentionPolicy, now_ns: i64) -> Vec<CheckpointId> {
        let live: Vec<&CheckpointRecord> = self
            .records
            .iter()
            .filter(|r| !self.is_pruned(r.id))
            .collect();
        let Some(head) = self.head() else {
            return Vec::new();
        };
        let candidates: Vec<&CheckpointRecord> = match policy {
            RetentionPolicy::KeepLast(n) => {
                let drop = live.len().saturating_sub(n.max(1));
                live.into_iter().take(drop).collect()
            }
            RetentionPolicy::OlderThan(age_ns) => {
                let cutoff = now_ns.saturating_sub(age_ns);
                live.into_iter().filter(|r| r.time_ns < cutoff).collect()
            }
        };
        candidates
            .into_iter()
            .filter(|r| r.id != head.id)
            .map(|r| r.id)
            .collect()
    }

    /// Marks checkpoints as removed. Their records stay in the chain.
    pub fn prune(&mut self, ids: &[CheckpointId]) -> DomainResult<Vec<DomainEvent>> {
        let head = self.head().map(|h| h.id);
        for id in ids {
            self.find(*id)?;
            if Some(*id) == head {
                return Err(DomainError::Refused(
                    "the newest checkpoint cannot be pruned".into(),
                ));
            }
            if self.is_pruned(*id) {
                return Err(DomainError::Refused(format!(
                    "checkpoint {id} is already pruned"
                )));
            }
        }
        let mut sorted: Vec<CheckpointId> = ids.to_vec();
        sorted.sort();
        sorted.dedup();
        for id in &sorted {
            self.pruned.insert(id.get());
        }
        Ok(if sorted.is_empty() {
            Vec::new()
        } else {
            vec![DomainEvent::CheckpointsPruned { ids: sorted }]
        })
    }

    /// Resolves a selector to the (non-pruned) checkpoints to undo, ascending.
    pub fn select(&self, sel: &Selector) -> DomainResult<Vec<CheckpointId>> {
        match sel {
            Selector::Checkpoint(id) => {
                let r = self.find(*id)?;
                if r.kind == CkptKind::Baseline {
                    return Err(DomainError::Usage(format!(
                        "checkpoint {id} is the baseline; there is nothing to undo"
                    )));
                }
                if self.is_pruned(r.id) {
                    return Err(DomainError::Refused(format!(
                        "checkpoint {id} was removed by gc; its data is gone"
                    )));
                }
                Ok(vec![r.id])
            }
            Selector::Last => self
                .records
                .iter()
                .rev()
                .find(|r| {
                    !matches!(r.kind, CkptKind::Baseline | CkptKind::PreUndo)
                        && r.counts.total() > 0
                        && !self.is_pruned(r.id)
                })
                .map(|r| vec![r.id])
                .ok_or_else(|| {
                    DomainError::Usage("no checkpoint with recorded changes to undo".into())
                }),
            Selector::Session(s) => {
                let session = match s {
                    Some(s) => *s,
                    None => self
                        .current_session()
                        .ok_or_else(|| DomainError::Usage("the log is empty".into()))?,
                };
                let ids: Vec<CheckpointId> = self
                    .records
                    .iter()
                    .filter(|r| r.session == session && r.kind != CkptKind::Baseline)
                    .map(|r| r.id)
                    .collect();
                if ids.is_empty() {
                    return Err(DomainError::Usage(format!(
                        "session {session} has no checkpoints to undo"
                    )));
                }
                if let Some(p) = ids.iter().find(|i| self.is_pruned(**i)) {
                    return Err(DomainError::Refused(format!(
                        "checkpoint {p} of session {session} was removed by gc; the session cannot be undone as a whole"
                    )));
                }
                Ok(ids)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nc(kind: CkptKind, t: i64, created: u64) -> NewCheckpoint {
        NewCheckpoint::new(
            kind,
            t,
            sha256(&t.to_le_bytes()),
            sha256(b"c"),
            Counts {
                created,
                ..Counts::default()
            },
            3,
        )
    }

    fn with_ref(mut n: NewCheckpoint, r: u64) -> NewCheckpoint {
        n.reference = Some(CheckpointId::new(r).unwrap());
        n
    }

    fn id(n: u64) -> CheckpointId {
        CheckpointId::new(n).unwrap()
    }

    fn journal_with(kinds: &[(CkptKind, bool)]) -> Journal {
        let mut j = Journal::empty();
        for (i, (k, new_session)) in kinds.iter().enumerate() {
            let mut n = nc(*k, (i as i64 + 1) * 100, 1);
            n.new_session = *new_session;
            if k.needs_reference() {
                n.reference = Some(id(1));
            }
            j.record(n).unwrap();
        }
        j
    }

    #[test]
    fn ids_and_sessions_reject_zero() {
        assert!(CheckpointId::new(0).is_err());
        assert!(SessionId::new(0).is_err());
        assert_eq!(CheckpointId::new(7).unwrap().to_string(), "#7");
        assert_eq!(SessionId::new(2).unwrap().to_string(), "2");
    }

    #[test]
    fn label_is_bounded() {
        assert!(Label::new(vec![b'a'; MAX_LABEL_BYTES]).is_ok());
        assert!(matches!(
            Label::new(vec![b'a'; MAX_LABEL_BYTES + 1]),
            Err(DomainError::Usage(_))
        ));
    }

    #[test]
    fn command_line_truncates_with_marker() {
        let args: Vec<Vec<u8>> = (0..1000).map(|_| vec![b'a'; 100]).collect();
        let c = CommandLine::bounded(&args);
        assert!(c.args().len() < 100);
        assert_eq!(c.args().last().unwrap(), b"...[truncated]");
        let small = vec![b"ls".to_vec()];
        assert_eq!(CommandLine::bounded(&small).args(), small.as_slice());
    }

    #[test]
    fn first_record_must_be_baseline_and_only_the_first() {
        let mut j = Journal::empty();
        assert!(matches!(
            j.record(nc(CkptKind::Run, 1, 0)),
            Err(DomainError::Refused(_))
        ));
        assert!(
            j.is_empty(),
            "a refused record leaves the journal untouched"
        );
        j.record(nc(CkptKind::Baseline, 1, 0)).unwrap();
        assert!(matches!(
            j.record(nc(CkptKind::Baseline, 2, 0)),
            Err(DomainError::Refused(_))
        ));
        assert_eq!(j.records().len(), 1);
    }

    #[test]
    fn baseline_opens_session_one_and_cannot_request_a_new_session() {
        let mut j = Journal::empty();
        let mut n = nc(CkptKind::Baseline, 1, 0);
        n.new_session = true;
        assert!(j.record(n).is_err());
        let (rec, _) = j.record(nc(CkptKind::Baseline, 1, 0)).unwrap();
        assert_eq!(rec.session.get(), 1);
        assert_eq!(rec.id.get(), 1);
    }

    #[test]
    fn negative_time_is_rejected() {
        let mut j = Journal::empty();
        assert!(matches!(
            j.record(nc(CkptKind::Baseline, -1, 0)),
            Err(DomainError::Invalid(_))
        ));
    }

    #[test]
    fn reference_rules() {
        let mut j = journal_with(&[(CkptKind::Baseline, false)]);
        assert!(
            j.record(nc(CkptKind::Undo, 5, 0)).is_err(),
            "undo needs a reference"
        );
        assert!(
            j.record(with_ref(nc(CkptKind::Run, 5, 0), 1)).is_err(),
            "run cannot reference"
        );
        assert!(
            j.record(with_ref(nc(CkptKind::Undo, 5, 0), 9)).is_err(),
            "reference must exist"
        );
        let (r, _) = j.record(with_ref(nc(CkptKind::Undo, 5, 0), 1)).unwrap();
        assert_eq!(r.reference, Some(id(1)));
    }

    #[test]
    fn record_emits_exactly_the_expected_events() {
        let mut j = Journal::empty();
        let (_, ev) = j.record(nc(CkptKind::Baseline, 1, 0)).unwrap();
        assert_eq!(
            ev,
            vec![
                DomainEvent::SessionStarted {
                    session: SessionId::new(1).unwrap()
                },
                DomainEvent::CheckpointRecorded {
                    id: id(1),
                    session: SessionId::new(1).unwrap(),
                    kind: CkptKind::Baseline,
                    changes: 0
                },
            ]
        );
        let (_, ev) = j.record(nc(CkptKind::Run, 2, 4)).unwrap();
        assert_eq!(
            ev,
            vec![DomainEvent::CheckpointRecorded {
                id: id(2),
                session: SessionId::new(1).unwrap(),
                kind: CkptKind::Run,
                changes: 4
            }],
            "no SessionStarted inside an existing session"
        );
        let mut n = nc(CkptKind::Run, 3, 0);
        n.new_session = true;
        let (rec, ev) = j.record(n).unwrap();
        assert_eq!(rec.session.get(), 2);
        assert!(
            matches!(ev.first(), Some(DomainEvent::SessionStarted { session }) if session.get() == 2)
        );
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn records_chain_hashes() {
        let j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Manual, false),
        ]);
        let r = j.records();
        assert_eq!(r[0].prev, GENESIS_PREV);
        assert_eq!(r[1].prev, r[0].hash);
        assert_eq!(r[2].prev, r[1].hash);
        for rec in r {
            assert_eq!(rec.hash, rec.compute_hash());
        }
    }

    #[test]
    fn record_text_round_trip_including_hostile_text() {
        let mut j = Journal::empty();
        j.record(nc(CkptKind::Baseline, 1, 0)).unwrap();
        let mut n = nc(CkptKind::Run, 2, 1);
        n.label = Some(Label::new(b"my label\n\x1b[0m".to_vec()).unwrap());
        n.command = Some(CommandLine::bounded(&[
            b"sh".to_vec(),
            b"-c".to_vec(),
            b"echo hi; \x1b[0m\t".to_vec(),
        ]));
        n.exit = Some(ExitInfo::Signal(9));
        let (rec, _) = j.record(n).unwrap();
        let line = rec.encode();
        assert!(!line.contains('\n'));
        assert_eq!(CheckpointRecord::decode(&line).unwrap(), rec);
    }

    #[test]
    fn decode_rejects_malformed_records() {
        let j = journal_with(&[(CkptKind::Baseline, false)]);
        let line = j.records()[0].encode();
        assert!(CheckpointRecord::decode("not a record").is_err());
        assert!(CheckpointRecord::decode(&format!("{line}\textra")).is_err());
        assert!(CheckpointRecord::decode(&line.replacen("baseline", "bogus", 1)).is_err());
        assert!(
            CheckpointRecord::decode(&line.replacen("1\t1\t", "0\t1\t", 1)).is_err(),
            "id 0"
        );
    }

    #[test]
    fn from_records_round_trips_and_detects_tampering() {
        let j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Manual, true),
        ]);
        let ok = Journal::from_records(j.records().to_vec(), BTreeSet::new()).unwrap();
        assert_eq!(ok.records(), j.records());

        let mut tampered = j.records().to_vec();
        tampered[1].counts.created = 99;
        assert!(matches!(
            Journal::from_records(tampered, BTreeSet::new()),
            Err(DomainError::Integrity(_))
        ));

        let mut dropped = j.records().to_vec();
        dropped.remove(1);
        assert!(matches!(
            Journal::from_records(dropped, BTreeSet::new()),
            Err(DomainError::Integrity(_))
        ));

        let mut reordered = j.records().to_vec();
        reordered.swap(1, 2);
        assert!(Journal::from_records(reordered, BTreeSet::new()).is_err());

        let mut bad_prev = j.records().to_vec();
        bad_prev[2].prev = [7; 32];
        bad_prev[2].hash = bad_prev[2].compute_hash();
        assert!(
            Journal::from_records(bad_prev, BTreeSet::new()).is_err(),
            "re-hashing one record does not repair the chain"
        );
    }

    #[test]
    fn from_records_rejects_structural_violations() {
        // baseline not first
        let mut j = Journal::empty();
        j.record(nc(CkptKind::Baseline, 1, 0)).unwrap();
        let mut recs = j.records().to_vec();
        recs[0].kind = CkptKind::Run;
        recs[0].hash = recs[0].compute_hash();
        assert!(Journal::from_records(recs, BTreeSet::new()).is_err());
        // session jump
        let j = journal_with(&[(CkptKind::Baseline, false), (CkptKind::Run, false)]);
        let mut recs = j.records().to_vec();
        recs[1].session = SessionId::new(3).unwrap();
        recs[1].hash = recs[1].compute_hash();
        assert!(Journal::from_records(recs, BTreeSet::new()).is_err());
        // missing reference on undo
        let mut recs = journal_with(&[(CkptKind::Baseline, false), (CkptKind::Undo, false)])
            .records()
            .to_vec();
        recs[1].reference = None;
        recs[1].hash = recs[1].compute_hash();
        assert!(Journal::from_records(recs, BTreeSet::new()).is_err());
        // unexpected reference on run
        let mut recs = journal_with(&[(CkptKind::Baseline, false), (CkptKind::Run, false)])
            .records()
            .to_vec();
        recs[1].reference = Some(id(1));
        recs[1].hash = recs[1].compute_hash();
        assert!(Journal::from_records(recs, BTreeSet::new()).is_err());
        // forward reference
        let mut recs = journal_with(&[(CkptKind::Baseline, false), (CkptKind::Undo, false)])
            .records()
            .to_vec();
        recs[1].reference = Some(id(2));
        recs[1].hash = recs[1].compute_hash();
        assert!(Journal::from_records(recs, BTreeSet::new()).is_err());
    }

    #[test]
    fn from_records_rejects_bad_pruned_lists() {
        let j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Run, false),
        ]);
        let recs = j.records().to_vec();
        assert!(Journal::from_records(recs.clone(), BTreeSet::from([1])).is_ok());
        assert!(
            Journal::from_records(recs.clone(), BTreeSet::from([3])).is_err(),
            "head cannot be pruned"
        );
        assert!(Journal::from_records(recs.clone(), BTreeSet::from([9])).is_err());
        assert!(Journal::from_records(recs, BTreeSet::from([0])).is_err());
    }

    #[test]
    fn find_and_head() {
        let j = journal_with(&[(CkptKind::Baseline, false), (CkptKind::Run, false)]);
        assert_eq!(j.find(id(2)).unwrap().kind, CkptKind::Run);
        assert!(matches!(j.find(id(3)), Err(DomainError::Usage(_))));
        assert_eq!(j.head().unwrap().id, id(2));
        assert_eq!(j.current_session().unwrap().get(), 1);
        assert!(Journal::empty().head().is_none());
        assert!(Journal::empty().current_session().is_none());
    }

    #[test]
    fn prune_rules_and_event() {
        let mut j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Run, false),
        ]);
        assert!(
            matches!(j.prune(&[id(3)]), Err(DomainError::Refused(_))),
            "head"
        );
        assert!(j.prune(&[id(9)]).is_err(), "unknown");
        let ev = j.prune(&[id(2), id(1), id(2)]).unwrap();
        assert_eq!(
            ev,
            vec![DomainEvent::CheckpointsPruned {
                ids: vec![id(1), id(2)]
            }]
        );
        assert!(j.is_pruned(id(1)) && j.is_pruned(id(2)) && !j.is_pruned(id(3)));
        assert!(
            matches!(j.prune(&[id(1)]), Err(DomainError::Refused(_))),
            "already pruned"
        );
        assert!(j.prune(&[]).unwrap().is_empty(), "nothing pruned, no event");
        assert_eq!(j.records().len(), 3, "records stay in the chain");
    }

    #[test]
    fn failed_prune_changes_nothing() {
        let mut j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Run, false),
        ]);
        assert!(j.prune(&[id(1), id(3)]).is_err());
        assert!(j.pruned().is_empty());
    }

    #[test]
    fn keep_last_selects_oldest_and_never_head() {
        let j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Run, false),
            (CkptKind::Run, false),
        ]);
        assert_eq!(
            j.prunable(RetentionPolicy::KeepLast(2), 0),
            vec![id(1), id(2)]
        );
        assert!(j.prunable(RetentionPolicy::KeepLast(10), 0).is_empty());
        assert_eq!(
            j.prunable(RetentionPolicy::KeepLast(1), 0),
            vec![id(1), id(2), id(3)]
        );
        assert!(RetentionPolicy::keep_last(0).is_err());
        assert_eq!(
            RetentionPolicy::keep_last(3).unwrap(),
            RetentionPolicy::KeepLast(3)
        );
    }

    #[test]
    fn keep_last_ignores_already_pruned() {
        let mut j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Run, false),
        ]);
        j.prune(&[id(1)]).unwrap();
        assert_eq!(j.prunable(RetentionPolicy::KeepLast(1), 0), vec![id(2)]);
    }

    #[test]
    fn older_than_uses_the_given_now_and_spares_head() {
        let j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Run, false),
        ]);
        // times are 100, 200, 300
        assert_eq!(
            j.prunable(RetentionPolicy::OlderThan(150), 400),
            vec![id(1), id(2)]
        );
        assert!(j.prunable(RetentionPolicy::OlderThan(1000), 400).is_empty());
        assert_eq!(
            j.prunable(RetentionPolicy::OlderThan(0), 10_000),
            vec![id(1), id(2)],
            "head is spared"
        );
        assert!(
            Journal::empty()
                .prunable(RetentionPolicy::KeepLast(1), 0)
                .is_empty()
        );
    }

    #[test]
    fn select_checkpoint() {
        let mut j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Run, false),
        ]);
        assert_eq!(j.select(&Selector::Checkpoint(id(2))).unwrap(), vec![id(2)]);
        assert!(
            matches!(
                j.select(&Selector::Checkpoint(id(1))),
                Err(DomainError::Usage(_))
            ),
            "baseline"
        );
        assert!(j.select(&Selector::Checkpoint(id(8))).is_err());
        j.prune(&[id(2)]).unwrap();
        assert!(matches!(
            j.select(&Selector::Checkpoint(id(2))),
            Err(DomainError::Refused(_))
        ));
    }

    #[test]
    fn select_last_skips_baseline_preundo_empty_and_pruned() {
        let mut j = Journal::empty();
        j.record(nc(CkptKind::Baseline, 1, 0)).unwrap();
        assert!(j.select(&Selector::Last).is_err(), "nothing to undo yet");
        j.record(nc(CkptKind::Run, 2, 2)).unwrap(); // #2 has changes
        j.record(nc(CkptKind::Manual, 3, 0)).unwrap(); // #3 empty
        j.record(with_ref(nc(CkptKind::PreUndo, 4, 5), 2)).unwrap(); // #4 pre-undo with drift
        assert_eq!(j.select(&Selector::Last).unwrap(), vec![id(2)]);
        j.record(nc(CkptKind::Watch, 5, 1)).unwrap(); // #5
        j.record(nc(CkptKind::Manual, 6, 0)).unwrap(); // #6 head, empty
        j.prune(&[id(5)]).unwrap();
        assert_eq!(
            j.select(&Selector::Last).unwrap(),
            vec![id(2)],
            "pruned #5 is skipped"
        );
    }

    #[test]
    fn select_session() {
        let j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Run, true),
            (CkptKind::Run, false),
        ]);
        assert_eq!(
            j.select(&Selector::Session(None)).unwrap(),
            vec![id(3), id(4)]
        );
        assert_eq!(
            j.select(&Selector::Session(Some(SessionId::new(1).unwrap())))
                .unwrap(),
            vec![id(2)],
            "baseline is not part of a session's undo set"
        );
        assert!(
            j.select(&Selector::Session(Some(SessionId::new(9).unwrap())))
                .is_err()
        );
        assert!(Journal::empty().select(&Selector::Session(None)).is_err());
    }

    #[test]
    fn select_session_refuses_when_part_was_pruned() {
        let mut j = journal_with(&[
            (CkptKind::Baseline, false),
            (CkptKind::Run, false),
            (CkptKind::Run, false),
            (CkptKind::Run, true),
        ]);
        j.prune(&[id(2)]).unwrap();
        assert!(matches!(
            j.select(&Selector::Session(Some(SessionId::new(1).unwrap()))),
            Err(DomainError::Refused(_))
        ));
    }

    #[test]
    fn exit_info_status_codes() {
        assert_eq!(ExitInfo::Code(3).status_code(), 3);
        assert_eq!(ExitInfo::Signal(9).status_code(), 137);
    }

    #[test]
    fn kind_names_round_trip() {
        for k in [
            CkptKind::Baseline,
            CkptKind::Run,
            CkptKind::Manual,
            CkptKind::External,
            CkptKind::Watch,
            CkptKind::PreUndo,
            CkptKind::Undo,
            CkptKind::Restore,
        ] {
            assert_eq!(CkptKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(CkptKind::parse("x"), None);
    }
}
