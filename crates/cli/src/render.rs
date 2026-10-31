//! Human-readable and JSON rendering of use case results.
//!
//! Everything that originates in the project (paths, symlink targets, labels,
//! command lines) is escaped with `esc::display` before it is printed, so a
//! hostile file name cannot inject terminal control sequences. Diffs never
//! print the content of sensitive files (the use case withholds it).

use crate::json::Json;
use agent_undo_app::error::Error;
use agent_undo_app::ports::ScanStats;
use agent_undo_app::usecases::gc::GcReport;
use agent_undo_app::usecases::history::{ChangeView, Content, DiffReport};
use agent_undo_app::usecases::reversal::ReversalReport;
use agent_undo_app::usecases::status::{Pending, StatusReport};
use agent_undo_app::usecases::verify::VerifyReport;
use agent_undo_domain::change::{Change, ChangeKind, Counts};
use agent_undo_domain::diff::DiffOutcome;
use agent_undo_domain::entry::{Entry, Kind};
use agent_undo_domain::esc::display;
use agent_undo_domain::hash::to_hex;
use agent_undo_domain::journal::{CheckpointRecord, ExitInfo, Journal};
use agent_undo_domain::path::RelPath;
use agent_undo_domain::plan::{Outcome, Plan, PlanItem};
use agent_undo_domain::units::{format_utc, human_size};

pub const SCHEMA: u64 = 1;

/// `{"schema":1,"ok":true,"command":<name>, ...}`
pub fn envelope(command: &str) -> Json {
    Json::obj()
        .with("schema", SCHEMA)
        .with("ok", true)
        .with("command", command)
}

/// `{"schema":1,"ok":false,"error":{"code":..,"message":..}}`
pub fn error_json(e: &Error) -> Json {
    Json::obj().with("schema", SCHEMA).with("ok", false).with(
        "error",
        Json::obj()
            .with("code", e.code())
            .with("message", display(e.to_string().as_bytes())),
    )
}

/// Scan warnings (unreadable files, degraded directories, ...), escaped, at most five lines.
pub fn warning_lines(stats: &ScanStats) -> Vec<String> {
    let mut out: Vec<String> = stats
        .warnings
        .iter()
        .take(5)
        .map(|w| format!("agent-undo: warning: {}", display(w.as_bytes())))
        .collect();
    let more = stats.warnings_total.saturating_sub(out.len() as u64);
    if more > 0 {
        out.push(format!("agent-undo: ... and {more} more warnings"));
    }
    out
}

pub fn warnings_json(stats: &ScanStats) -> Json {
    Json::obj()
        .with(
            "items",
            stats
                .warnings
                .iter()
                .map(|w| display(w.as_bytes()))
                .collect::<Vec<String>>(),
        )
        .with("total", stats.warnings_total)
}

/// `run --json` output when the command ran but its checkpoint could not be recorded.
pub fn run_not_recorded_json(e: &Error, exit_status: i32) -> Json {
    error_json(e)
        .with("exit_status", i64::from(exit_status))
        .with("recorded", false)
}

// ------------------------------------------------------------------ pieces

pub fn counts_text(c: &Counts) -> String {
    format!(
        "{} created, {} modified, {} deleted, {} mode-changed",
        c.created, c.modified, c.deleted, c.mode_changed
    )
}

pub fn counts_json(c: &Counts) -> Json {
    Json::obj()
        .with("created", c.created)
        .with("modified", c.modified)
        .with("deleted", c.deleted)
        .with("mode_changed", c.mode_changed)
        .with("total", c.total())
}

fn exit_text(e: Option<ExitInfo>) -> String {
    match e {
        None => "-".to_string(),
        Some(ExitInfo::Code(c)) => c.to_string(),
        Some(ExitInfo::Signal(s)) => format!("signal {s}"),
    }
}

fn exit_json(e: Option<ExitInfo>) -> Json {
    match e {
        None => Json::Null,
        Some(ExitInfo::Code(c)) => Json::obj().with("code", i64::from(c)),
        Some(ExitInfo::Signal(s)) => Json::obj().with("signal", i64::from(s)),
    }
}

pub fn command_text(rec: &CheckpointRecord) -> Option<String> {
    rec.command.as_ref().map(|c| {
        c.args()
            .iter()
            .map(|a| display(a))
            .collect::<Vec<_>>()
            .join(" ")
    })
}

pub fn record_json(rec: &CheckpointRecord, pruned: bool) -> Json {
    Json::obj()
        .with("id", rec.id.get())
        .with("session", rec.session.get())
        .with("kind", rec.kind.as_str())
        .with("time", format_utc(rec.time_ns))
        .with("time_ns", rec.time_ns)
        .with("label", rec.label.as_ref().map(|l| display(l.as_bytes())))
        .with(
            "command",
            rec.command.as_ref().map_or(Json::Null, |c| {
                Json::Arr(c.args().iter().map(|a| Json::from(display(a))).collect())
            }),
        )
        .with("exit", exit_json(rec.exit))
        .with("changes", counts_json(&rec.counts))
        .with("entries", rec.entries)
        .with("reference", rec.reference.map(|r| r.get()))
        .with("manifest_sha256", to_hex(&rec.manifest))
        .with("changes_sha256", to_hex(&rec.changes))
        .with("hash", to_hex(&rec.hash))
        .with("prev", to_hex(&rec.prev))
        .with("pruned", pruned)
}

fn mode_text(m: u32) -> String {
    format!("{m:04o}")
}

pub fn entry_json(e: &Entry) -> Json {
    let mut j = Json::obj()
        .with("kind", e.kind().as_str())
        .with("mode", mode_text(e.mode()))
        .with("size", e.size());
    match e.kind() {
        Kind::File | Kind::TooLarge => {
            j = j.with("sha256", e.digest().map(|d| to_hex(&d)));
        }
        Kind::Sensitive => {
            // Never print the keyed id; the file's content is not recorded.
            j = j.with("sensitive", true);
        }
        Kind::Symlink => {
            j = j.with("target", e.target().map(display));
        }
        _ => {}
    }
    j
}

fn opt_entry_json(e: Option<&Entry>) -> Json {
    e.map_or(Json::Null, entry_json)
}

fn path_fields(j: Json, p: &RelPath) -> Json {
    j.with("path", p.display()).with("path_pct", p.encode())
}

pub fn change_json(c: &Change) -> Json {
    path_fields(Json::obj().with("change", c.kind().as_str()), c.path())
        .with("before", opt_entry_json(c.before()))
        .with("after", opt_entry_json(c.after()))
}

// --------------------------------------------------------------------- init

pub fn init_text(root: &str, store: &str, rec: &CheckpointRecord, in_project: bool) -> String {
    format!(
        "initialized agent-undo for {root}\nstore: {store}{}\nbaseline: checkpoint {} ({} entries)\n",
        if in_project {
            " (inside the project; added to .git/info/exclude when a git directory exists)"
        } else {
            ""
        },
        rec.id,
        rec.entries
    )
}

// --------------------------------------------------------------------- log

pub fn log_text(journal: &Journal, only_session: Option<u64>) -> String {
    let mut out = String::from(
        "ID    SESSION  KIND       TIME (UTC)            CHANGES               EXIT    LABEL / COMMAND\n",
    );
    for r in journal.records() {
        if only_session.is_some_and(|s| s != r.session.get()) {
            continue;
        }
        let what = match (&r.label, command_text(r)) {
            (Some(l), Some(c)) => format!("{}: {c}", display(l.as_bytes())),
            (Some(l), None) => display(l.as_bytes()),
            (None, Some(c)) => c,
            (None, None) => String::new(),
        };
        let ch = format!(
            "+{} ~{} -{} m{}",
            r.counts.created, r.counts.modified, r.counts.deleted, r.counts.mode_changed
        );
        out.push_str(&format!(
            "{:<5} {:<8} {:<10} {} {:<21} {:<7} {}{}\n",
            format!("#{}", r.id.get()),
            r.session.get(),
            r.kind.as_str(),
            format_utc(r.time_ns),
            ch,
            exit_text(r.exit),
            what,
            if journal.is_pruned(r.id) {
                "  (pruned)"
            } else {
                ""
            }
        ));
    }
    out
}

pub fn log_json(journal: &Journal, only_session: Option<u64>) -> Json {
    let items: Vec<Json> = journal
        .records()
        .iter()
        .filter(|r| only_session.is_none_or(|s| s == r.session.get()))
        .map(|r| record_json(r, journal.is_pruned(r.id)))
        .collect();
    envelope("log")
        .with("checkpoints", Json::Arr(items))
        .with("head_hash", journal.head().map(|h| to_hex(&h.hash)))
}

// -------------------------------------------------------------------- diff

fn change_letter(k: ChangeKind) -> &'static str {
    match k {
        ChangeKind::Created => "A",
        ChangeKind::Deleted => "D",
        ChangeKind::Modified => "M",
        ChangeKind::ModeChanged => "T",
    }
}

fn describe_entry(e: &Entry) -> String {
    match e.kind() {
        Kind::Symlink => format!("symlink -> {}", e.target().map(display).unwrap_or_default()),
        Kind::Dir => format!("dir {}", mode_text(e.mode())),
        k => format!(
            "{} {} {}",
            k.as_str(),
            mode_text(e.mode()),
            human_size(e.size())
        ),
    }
}

fn view_line(v: &ChangeView) -> String {
    let c = &v.change;
    let mut line = format!("{}  {}", change_letter(c.kind()), c.path().display());
    match (c.kind(), c.before(), c.after()) {
        (ChangeKind::ModeChanged, Some(b), Some(a)) => {
            line.push_str(&format!(
                "  (mode {} -> {})",
                mode_text(b.mode()),
                mode_text(a.mode())
            ));
        }
        (_, _, Some(a)) if c.kind() != ChangeKind::Modified || a.kind() != Kind::File => {
            line.push_str(&format!("  ({})", describe_entry(a)));
        }
        (_, Some(b), None) if b.kind() != Kind::File => {
            line.push_str(&format!("  ({})", describe_entry(b)))
        }
        _ => {}
    }
    line
}

pub fn diff_text(r: &DiffReport) -> String {
    let rec = &r.record;
    let mut out = format!(
        "checkpoint {} ({}, session {}) {}  exit {}\n",
        rec.id,
        rec.kind.as_str(),
        rec.session,
        format_utc(rec.time_ns),
        exit_text(rec.exit)
    );
    if let Some(l) = &rec.label {
        out.push_str(&format!("label: {}\n", display(l.as_bytes())));
    }
    if let Some(c) = command_text(rec) {
        out.push_str(&format!("command: {c}\n"));
    }
    out.push_str(&format!("changes: {}\n", counts_text(&rec.counts)));
    let renamed_from: std::collections::HashSet<&RelPath> =
        r.renames.iter().map(|x| &x.from).collect();
    let renamed_to: std::collections::HashMap<&RelPath, &RelPath> =
        r.renames.iter().map(|x| (&x.to, &x.from)).collect();
    for v in &r.changes {
        let p = v.change.path();
        if renamed_from.contains(p) {
            continue; // shown on the rename line
        }
        if let Some(from) = renamed_to.get(p) {
            out.push_str(&format!("R  {} -> {}\n", from.display(), p.display()));
            continue;
        }
        out.push_str(&view_line(v));
        out.push('\n');
        match &v.content {
            Content::Withheld("directory" | "symlink") => {}
            Content::Withheld(why) => out.push_str(&format!("    ({why})\n")),
            Content::Diff(DiffOutcome::Text(t)) => {
                let name = p.display();
                let (a, b) = match v.change.kind() {
                    ChangeKind::Created => ("/dev/null".to_string(), format!("b/{name}")),
                    ChangeKind::Deleted => (format!("a/{name}"), "/dev/null".to_string()),
                    _ => (format!("a/{name}"), format!("b/{name}")),
                };
                out.push_str(&format!("--- {a}\n+++ {b}\n"));
                for l in t.lines() {
                    out.push_str(l); // already escaped by the domain diff
                    out.push('\n');
                }
            }
            Content::Diff(DiffOutcome::Omitted(why)) => {
                out.push_str(&format!("    (no text diff: {why})\n"))
            }
            Content::Diff(DiffOutcome::Identical) => {}
        }
    }
    if r.truncated {
        out.push_str("... more changes not shown (limit reached)\n");
    }
    out
}

pub fn diff_json(r: &DiffReport) -> Json {
    let changes: Vec<Json> = r
        .changes
        .iter()
        .map(|v| {
            let base = change_json(&v.change);
            match &v.content {
                Content::Withheld(why) => base.with("text_diff", Json::Null).with("withheld", *why),
                Content::Diff(DiffOutcome::Text(t)) => base.with("text_diff", t.as_str()),
                Content::Diff(DiffOutcome::Omitted(why)) => base
                    .with("text_diff", Json::Null)
                    .with("diff_omitted", *why),
                Content::Diff(DiffOutcome::Identical) => base.with("text_diff", Json::Null),
            }
        })
        .collect();
    let renames: Vec<Json> = r
        .renames
        .iter()
        .map(|x| {
            Json::obj()
                .with("from", x.from.display())
                .with("to", x.to.display())
        })
        .collect();
    envelope("diff")
        .with("checkpoint", record_json(&r.record, false))
        .with("changes", Json::Arr(changes))
        .with("renames", Json::Arr(renames))
        .with("truncated", r.truncated)
}

// ------------------------------------------------------------- undo/restore

fn item_line(i: &PlanItem, outcome: Option<&Outcome>) -> String {
    let status = match outcome {
        Some(Outcome::Applied) => "applied".to_string(),
        Some(Outcome::Skipped(why)) => format!("skipped: {why}"),
        Some(Outcome::Failed(why)) => format!("FAILED: {why}"),
        Some(Outcome::NotAttempted) => "not attempted".to_string(),
        None => match i.status.reason() {
            Some(r) => format!("{}: {r}", i.status.as_str().replace('-', " ")),
            None => i.status.as_str().replace('-', " "),
        },
    };
    format!("  {:<8} {}  [{}]", i.op.as_str(), i.path.display(), status)
}

pub fn plan_text(plan: &Plan, report: Option<&ReversalReport>, apply: bool) -> String {
    let mut out = String::new();
    let mode = if report
        .is_some_and(|r| r.refused.is_none() && (r.result.is_some() || r.error.is_some()))
    {
        "applied"
    } else if apply {
        "apply requested"
    } else {
        "dry run - nothing was changed; re-run with --apply to apply"
    };
    out.push_str(&format!("{} ({mode})\n", plan.description));
    for (idx, item) in plan.items.iter().enumerate() {
        let outcome = report.and_then(|r| r.outcomes.get(idx));
        let shown = outcome.filter(|o| {
            !matches!(o, Outcome::NotAttempted) || report.is_some_and(|r| r.result.is_some())
        });
        out.push_str(&item_line(item, shown));
        out.push('\n');
    }
    let c = plan.counts();
    out.push_str(&format!(
        "summary: {} ready, {} conflicts, {} already done, {} not restorable, {} blocked\n",
        c.ready, c.conflicts, c.already_done, c.not_restorable, c.blocked
    ));
    if let Some(r) = report {
        if let Some(why) = &r.refused {
            out.push_str(&format!("refused: {why}\n"));
        }
        if let Some(e) = &r.error {
            out.push_str(&format!("error: {e}\n"));
        }
        if let Some(p) = &r.pre_undo {
            out.push_str(&format!("saved current state as {} (pre-undo)\n", p.id));
        }
        if let Some(res) = &r.result {
            out.push_str(&format!(
                "recorded {} as checkpoint {}; {} applied, {} skipped. Undo this with: agent-undo undo {} --apply\n",
                res.kind.as_str(),
                res.id,
                r.applied(),
                r.skipped(),
                res.id.get()
            ));
        }
        if r.refused.is_none() && r.result.is_none() && r.error.is_none() {
            out.push_str("nothing to do\n");
        }
    } else if plan.has_conflicts() {
        out.push_str("note: conflicting paths need --force\n");
    }
    out
}

pub fn plan_json(command: &str, plan: &Plan, report: Option<&ReversalReport>, apply: bool) -> Json {
    let items: Vec<Json> = plan
        .items
        .iter()
        .enumerate()
        .map(|(idx, i)| {
            let mut j = path_fields(Json::obj(), &i.path)
                .with("op", i.op.as_str())
                .with("status", i.status.as_str())
                .with("reason", i.status.reason().map(str::to_string))
                .with("target", opt_entry_json(i.target.as_ref()))
                .with("current", opt_entry_json(i.current.as_ref()));
            if let Some(o) = report.and_then(|r| r.outcomes.get(idx)) {
                j = j.with("outcome", o.as_str());
                if let Outcome::Skipped(w) | Outcome::Failed(w) = o {
                    j = j.with("outcome_detail", display(w.as_bytes()));
                }
            }
            j
        })
        .collect();
    let c = plan.counts();
    let mut j = envelope(command)
        .with("description", display(plan.description.as_bytes()))
        .with("kind", plan.kind.as_str())
        .with(
            "sources",
            plan.sources.iter().map(|s| s.get()).collect::<Vec<u64>>(),
        )
        .with("apply_requested", apply)
        .with(
            "counts",
            Json::obj()
                .with("ready", c.ready)
                .with("conflicts", c.conflicts)
                .with("already_done", c.already_done)
                .with("not_restorable", c.not_restorable)
                .with("blocked", c.blocked),
        )
        .with("items", Json::Arr(items));
    if let Some(r) = report {
        j = j
            .with("applied", r.result.is_some())
            .with("refused", r.refused.clone())
            .with("error", r.error.as_deref().map(|e| display(e.as_bytes())))
            .with("applied_count", r.applied())
            .with("skipped_count", r.skipped())
            .with(
                "pre_undo_checkpoint",
                r.pre_undo.as_ref().map(|p| p.id.get()),
            )
            .with("result_checkpoint", r.result.as_ref().map(|p| p.id.get()));
    } else {
        j = j.with("applied", false);
    }
    j
}

// ------------------------------------------------------------------ status

pub fn pending_text(p: &Pending) -> String {
    if p.counts.total() == 0 {
        "none (the project matches the last checkpoint)".to_string()
    } else {
        format!("{} (not yet checkpointed)", counts_text(&p.counts))
    }
}

pub fn status_text(root: &str, store: &str, r: &StatusReport) -> String {
    let mut out = format!("project: {root}\nstore: {store}\n");
    if r.locked_by_other {
        out.push_str(
            "lock: held by another agent-undo operation (details unavailable until it finishes)\n",
        );
        return out;
    }
    out.push_str(&format!("checkpoints: {}", r.checkpoints));
    if let Some(s) = r.session {
        out.push_str(&format!(" (current session {s})"));
    }
    if r.pruned > 0 {
        out.push_str(&format!(", {} pruned", r.pruned));
    }
    out.push('\n');
    if let Some(h) = &r.head {
        out.push_str(&format!(
            "last: {} {} {}\n",
            h.id,
            h.kind.as_str(),
            format_utc(h.time_ns)
        ));
    }
    if let Some(p) = &r.pending {
        out.push_str(&format!("pending changes: {}\n", pending_text(p)));
        for w in &p.stats.warnings {
            out.push_str(&format!("warning: {}\n", display(w.as_bytes())));
        }
    }
    out
}

pub fn status_json(root: &str, store: &str, r: &StatusReport) -> Json {
    let pending = r.pending.as_ref().map(|p| {
        Json::obj()
            .with("counts", counts_json(&p.counts))
            .with(
                "sample",
                Json::Arr(p.sample.iter().take(50).map(change_json).collect()),
            )
            .with(
                "warnings",
                p.stats
                    .warnings
                    .iter()
                    .map(|w| display(w.as_bytes()))
                    .collect::<Vec<String>>(),
            )
    });
    envelope("status")
        .with("project", root)
        .with("store", store)
        .with("locked_by_other", r.locked_by_other)
        .with("checkpoints", r.checkpoints)
        .with("pruned", r.pruned)
        .with("session", r.session.map(|s| s.get()))
        .with("head", r.head.as_ref().map(|h| record_json(h, false)))
        .with("pending", pending.unwrap_or(Json::Null))
}

// ------------------------------------------------------------ verify and gc

pub fn verify_text(r: &VerifyReport) -> String {
    let mut out = String::new();
    for w in &r.warnings {
        out.push_str(&format!("warning: {w}\n"));
    }
    for p in &r.problems {
        out.push_str(&format!("PROBLEM: {p}\n"));
    }
    out.push_str(&format!(
        "verify: {} - {} checkpoints checked ({} pruned), {} blobs checked ({} unreferenced)\n",
        if r.ok() { "ok" } else { "FAILED" },
        r.checkpoints_checked,
        r.checkpoints_pruned,
        r.blobs_checked,
        r.blobs_unreferenced
    ));
    out
}

pub fn verify_json(r: &VerifyReport) -> Json {
    envelope("verify")
        .with("verified", r.ok())
        .with("checkpoints_checked", r.checkpoints_checked)
        .with("checkpoints_pruned", r.checkpoints_pruned)
        .with("blobs_checked", r.blobs_checked)
        .with("blobs_unreferenced", r.blobs_unreferenced)
        .with(
            "problems",
            r.problems
                .iter()
                .map(|p| display(p.as_bytes()))
                .collect::<Vec<String>>(),
        )
        .with(
            "warnings",
            r.warnings
                .iter()
                .map(|p| display(p.as_bytes()))
                .collect::<Vec<String>>(),
        )
}

pub fn gc_text(r: &GcReport) -> String {
    let ids: Vec<String> = r.checkpoints.iter().map(ToString::to_string).collect();
    format!(
        "gc {}: {} checkpoints {}{}, {} blobs ({}) {}; {} checkpoints kept\n{}",
        if r.applied { "applied" } else { "dry run" },
        r.checkpoints.len(),
        if r.applied {
            "pruned"
        } else {
            "would be pruned"
        },
        if ids.is_empty() {
            String::new()
        } else {
            format!(" [{}]", ids.join(", "))
        },
        r.blobs,
        human_size(r.blob_bytes),
        if r.applied {
            "deleted"
        } else {
            "would be deleted"
        },
        r.retained,
        if r.applied {
            ""
        } else {
            "re-run with --apply to delete them\n"
        }
    )
}

pub fn gc_json(r: &GcReport) -> Json {
    envelope("gc")
        .with("applied", r.applied)
        .with(
            "checkpoints",
            r.checkpoints.iter().map(|c| c.get()).collect::<Vec<u64>>(),
        )
        .with("blobs", r.blobs)
        .with("blob_bytes", r.blob_bytes)
        .with("retained", r.retained)
}

#[cfg(test)]
mod tests;
