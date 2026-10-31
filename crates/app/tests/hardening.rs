//! Application-level tests (use cases against in-memory fakes) for the security
//! review findings: sensitive copies, degraded scans, redacted command lines and the
//! behaviour of `run` when recording fails.

use agent_undo_app::error::Error;
use agent_undo_app::events::Event;
use agent_undo_app::fakes::{MemTree, World};
use agent_undo_app::ports::{RunOutcome, RunRequest};
use agent_undo_app::usecases::checkpoint::manual_checkpoint;
use agent_undo_app::usecases::init::record_baseline;
use agent_undo_app::usecases::reversal::apply_undo;
use agent_undo_app::usecases::run::{RunCommand, RunFailure, RunReport, run_command};
use agent_undo_domain::change::EntrySource;
use agent_undo_domain::entry::Kind;
use agent_undo_domain::env::EnvPolicy;
use agent_undo_domain::journal::{ArgPolicy, CheckpointId, DomainEvent, ExitInfo, Label, Selector};

use std::cell::RefCell;
use std::rc::Rc;

const PLAIN_SECRET: &[u8] = b"hunter2\n";

fn world_with(action: impl Fn(&RunRequest) + 'static, code: i32) -> World {
    World::with_runner(agent_undo_app::fakes::ScriptedRunner::new(
        action,
        RunOutcome::Exited(ExitInfo::Code(code)),
    ))
}

fn args(a: &[&str]) -> Vec<Vec<u8>> {
    a.iter().map(|s| s.as_bytes().to_vec()).collect()
}

fn run_with(w: &World, a: &[&str], policy: ArgPolicy) -> Result<RunReport, RunFailure> {
    w.with_ports(|p| {
        run_command(
            p,
            RunCommand {
                args: args(a),
                label: None,
                new_session: false,
                env: EnvPolicy::Inherit,
                arg_policy: policy,
            },
        )
    })
}

fn journal_records(w: &World) -> Vec<agent_undo_domain::journal::CheckpointRecord> {
    use agent_undo_app::ports::JournalRepository;
    w.journal.load().unwrap().records().to_vec()
}

fn baseline(w: &World) {
    w.with_ports(record_baseline).unwrap();
    w.events.clear();
}

fn entry_kind(w: &World, id: u64, path: &str) -> Option<Kind> {
    let mut m = w.snapshots_open(id);
    while let Some((p, e)) = m.next_entry().unwrap() {
        if p.display() == path {
            return Some(e.kind());
        }
    }
    None
}

trait OpenManifest {
    fn snapshots_open(&self, id: u64) -> agent_undo_app::ports::ManifestStream;
}

impl OpenManifest for World {
    fn snapshots_open(&self, id: u64) -> agent_undo_app::ports::ManifestStream {
        use agent_undo_app::ports::SnapshotRepository;
        self.snapshots
            .open_manifest(CheckpointId::new(id).unwrap())
            .unwrap()
    }
}

// ------------------------------------------------------------- SU-001 through the use cases

#[test]
fn a_copy_made_by_the_agent_is_recorded_as_sensitive_and_never_stored() {
    let w = world_with(
        |_| {
            // the "agent": cp .env settings.txt
        },
        0,
    );
    w.tree.write(".env", PLAIN_SECRET);
    baseline(&w);
    assert_eq!(entry_kind(&w, 1, ".env"), Some(Kind::Sensitive));
    w.tree.write("settings.txt", PLAIN_SECRET);
    w.tree.write("notes.txt", b"ordinary");
    let rep = run_with(&w, &["true"], ArgPolicy::Redact).unwrap();
    assert_eq!(
        entry_kind(&w, rep.checkpoint.id.get(), "settings.txt"),
        Some(Kind::Sensitive)
    );
    assert_eq!(
        entry_kind(&w, rep.checkpoint.id.get(), "notes.txt"),
        Some(Kind::File)
    );
    let stored = w.blobs.all_bytes();
    assert!(
        !stored.windows(7).any(|x| x == b"hunter2"),
        "a copy of a secret reached the blob store"
    );
}

#[test]
fn withholding_a_secret_copy_is_announced_exactly_once_per_new_path() {
    let w = world_with(|_| {}, 0);
    w.tree.write(".env", PLAIN_SECRET);
    baseline(&w);
    w.tree.write("settings.txt", PLAIN_SECRET);
    manual(&w);
    let withheld: Vec<String> = w
        .events
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::SensitiveContentWithheld { path } => Some(path.display()),
            _ => None,
        })
        .collect();
    assert_eq!(withheld, vec!["settings.txt".to_string()]);
    w.events.clear();
    manual(&w);
    assert!(
        !w.events
            .events()
            .iter()
            .any(|e| matches!(e, Event::SensitiveContentWithheld { .. })),
        "an unchanged sensitive file is not announced again"
    );
}

fn manual(w: &World) {
    w.with_ports(|p| manual_checkpoint(p, None, false)).unwrap();
}

#[test]
fn undo_never_deletes_or_rewrites_a_secret_copy() {
    let w = world_with(|_| {}, 0);
    w.tree.write(".env", PLAIN_SECRET);
    baseline(&w);
    w.tree.write("copy.txt", PLAIN_SECRET);
    w.tree.write("plain.txt", b"x");
    run_with(&w, &["true"], ArgPolicy::Redact).unwrap();
    let rep = w
        .with_ports(|p| apply_undo(p, &Selector::Last, false))
        .unwrap();
    assert!(rep.error.is_none() && rep.refused.is_none());
    assert!(
        w.tree.exists("copy.txt"),
        "undo must not touch the secret copy"
    );
    assert_eq!(w.tree.read("copy.txt").unwrap(), PLAIN_SECRET);
    assert!(
        !w.tree.exists("plain.txt"),
        "ordinary files are still undone"
    );
}

// ---------------------------------------------------- SU-007 recorded command lines

#[test]
fn the_recorded_command_line_is_redacted() {
    let w = world_with(|_| {}, 0);
    baseline(&w);
    let rep = run_with(
        &w,
        &[
            "deploy",
            "--password",
            "hunter2",
            "--api-key=hunter3x",
            "DB_TOKEN=hunter4y",
            "--region",
            "eu",
        ],
        ArgPolicy::Redact,
    )
    .unwrap();
    let cmd = rep.checkpoint.command.as_ref().unwrap();
    let joined: Vec<u8> = cmd.args().concat();
    for secret in ["hunter2", "hunter3x", "hunter4y"] {
        assert!(
            !joined.windows(secret.len()).any(|x| x == secret.as_bytes()),
            "{secret}"
        );
    }
    assert_eq!(cmd.args().len(), 7, "argument positions are kept");
    assert_eq!(cmd.args().first().unwrap(), b"deploy");
    assert_eq!(cmd.args().last().unwrap(), b"eu");
    // what the journal stores is what was recorded
    let j = journal_records(&w);
    assert_eq!(
        j.last().unwrap().command.as_ref().unwrap().args(),
        cmd.args()
    );
}

#[test]
fn the_command_receives_its_real_arguments_even_though_the_log_is_redacted() {
    let w = world_with(|_| {}, 0);
    baseline(&w);
    run_with(&w, &["tool", "--password", "hunter2"], ArgPolicy::Redact).unwrap();
    assert_eq!(
        w.runner.requests()[0].args,
        args(&["tool", "--password", "hunter2"])
    );
}

#[test]
fn omit_policy_records_only_the_program() {
    let w = world_with(|_| {}, 0);
    baseline(&w);
    let rep = run_with(&w, &["tool", "--flag", "value"], ArgPolicy::Omit).unwrap();
    assert_eq!(
        rep.checkpoint.command.as_ref().unwrap().args(),
        &[b"tool".to_vec(), b"[args omitted]".to_vec()]
    );
}

#[test]
fn user_labels_are_redacted_by_the_domain_constructor() {
    assert_eq!(
        Label::user(b"nightly".to_vec()).unwrap().as_bytes(),
        b"nightly"
    );
    assert_eq!(
        Label::user(b"DB_PASSWORD=hunter2".to_vec())
            .unwrap()
            .as_bytes(),
        b"[redacted]"
    );
}

// ------------------------------------------------- SU-002 recording must not fail the run

#[test]
fn run_keeps_the_commands_status_and_reports_not_recorded_when_the_journal_cannot_append() {
    // the "agent" creates a file through a handle to the tree that is filled in below
    let slot: Rc<RefCell<Option<Rc<MemTree>>>> = Rc::new(RefCell::new(None));
    let handle = slot.clone();
    let w = world_with(
        move |_| {
            if let Some(t) = handle.borrow().as_ref() {
                t.write("b.txt", b"made by the command");
            }
        },
        3,
    );
    *slot.borrow_mut() = Some(w.tree.clone());
    w.tree.write("a.txt", b"a");
    baseline(&w);
    w.journal.set_fail_appends(true);
    let err = run_with(&w, &["tool"], ArgPolicy::Redact).unwrap_err();
    match err {
        RunFailure::NotRecorded { exit, error } => {
            assert_eq!(exit, ExitInfo::Code(3), "the command's own status survives");
            assert!(matches!(error, Error::Other(_)), "{error}");
        }
        other => panic!("{other:?}"),
    }
    assert!(w.tree.exists("b.txt"), "nothing is rolled back");
    let events = w.events.events();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::CommandFinished {
            exit: ExitInfo::Code(3)
        }
    )));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::Domain(DomainEvent::CheckpointRecorded { .. }))),
        "no checkpoint was recorded: {events:?}"
    );
    // once storage works again the command's changes are caught by the next checkpoint
    w.journal.set_fail_appends(false);
    manual(&w);
    assert_eq!(journal_records(&w).last().unwrap().counts.created, 1);
}

#[test]
fn a_failing_before_snapshot_stops_the_run_without_executing_the_command() {
    let w = world_with(|_| {}, 0);
    w.tree.write("a.txt", b"a");
    baseline(&w);
    w.tree.write("edited-by-hand.txt", b"x");
    w.journal.set_fail_appends(true);
    let err = run_with(&w, &["tool"], ArgPolicy::Redact).unwrap_err();
    assert!(matches!(err, RunFailure::Internal(_)), "{err:?}");
    assert!(
        w.runner.requests().is_empty(),
        "the command must not run unrecorded"
    );
}

#[test]
fn a_directory_over_the_entry_cap_degrades_and_the_run_succeeds_with_warnings() {
    let w = world_with(|_| {}, 5);
    w.tree.set_limits(5, 256);
    for i in 0..3 {
        w.tree.write(&format!("big/old{i}.txt"), b"old");
    }
    baseline(&w);
    for i in 0..10 {
        w.tree.write(&format!("big/new{i}.txt"), b"new");
    }
    w.tree.write("small.txt", b"s");
    let rep = run_with(&w, &["tool"], ArgPolicy::Redact).unwrap();
    assert_eq!(rep.exit, ExitInfo::Code(5));
    assert!(
        rep.stats
            .warnings
            .iter()
            .any(|x| x.contains("more than 5 entries")),
        "{:?}",
        rep.stats.warnings
    );
    // old entries below the degraded directory are kept, not reported as deleted
    assert_eq!(rep.checkpoint.counts.deleted, 0);
    assert_eq!(
        entry_kind(&w, rep.checkpoint.id.get(), "big/old0.txt"),
        Some(Kind::File)
    );
    assert_eq!(
        entry_kind(&w, rep.checkpoint.id.get(), "big/new0.txt"),
        None
    );
    assert_eq!(
        entry_kind(&w, rep.checkpoint.id.get(), "small.txt"),
        Some(Kind::File)
    );
    // later checkpoints keep working
    manual(&w);
}

#[test]
fn a_hostile_ignore_file_degrades_to_the_defaults_and_does_not_fail_recording() {
    let w = world_with(|_| {}, 0);
    baseline(&w);
    w.tree.write(".agent-undoignore", &vec![b'x'; 6000]);
    w.tree.write("a.txt", b"a");
    let rep = run_with(&w, &["tool"], ArgPolicy::Redact).unwrap();
    assert!(
        rep.stats
            .warnings
            .iter()
            .any(|x| x.contains(".agent-undoignore"))
    );
    // both files were made before the run, so the before-snapshot recorded them
    assert_eq!(rep.external.as_ref().unwrap().counts.created, 2);
}

#[test]
fn the_root_over_the_cap_carries_every_previous_entry_forward() {
    let w = world_with(|_| {}, 0);
    w.tree.set_limits(3, 256);
    w.tree.write("a.txt", b"a");
    w.tree.write("b.txt", b"b");
    baseline(&w);
    for i in 0..5 {
        w.tree.write(&format!("flood{i}.txt"), b"x");
    }
    let rep = run_with(&w, &["tool"], ArgPolicy::Redact).unwrap();
    assert_eq!(
        rep.checkpoint.counts.total(),
        0,
        "{:?}",
        rep.checkpoint.counts
    );
    assert!(
        rep.stats
            .warnings
            .iter()
            .any(|x| x.contains("project root"))
    );
    assert_eq!(
        entry_kind(&w, rep.checkpoint.id.get(), "a.txt"),
        Some(Kind::File)
    );
    assert_eq!(entry_kind(&w, rep.checkpoint.id.get(), "flood0.txt"), None);
}
