//! Command handlers: translate parsed arguments into use case calls and print
//! the results.

use crate::args::{Cli, Command, GcPolicy, UndoTarget, WatchOpts};
use crate::doctor::{Status, doctor_json, doctor_text, run_checks};
use crate::json::Json;
use crate::render::{self, envelope};
use agent_undo_app::error::{Error, Result, exit};
use agent_undo_app::usecases::checkpoint::{load_log, manual_checkpoint};
use agent_undo_app::usecases::gc::gc;
use agent_undo_app::usecases::history::diff_checkpoint;
use agent_undo_app::usecases::init::record_baseline;
use agent_undo_app::usecases::reversal::{apply_restore, apply_undo, plan_restore, plan_undo};
use agent_undo_app::usecases::run::{RunCommand, RunFailure, run_command};
use agent_undo_app::usecases::status::status;
use agent_undo_app::usecases::verify::verify;
use agent_undo_app::usecases::watch::watch_tick;
use agent_undo_domain::env::EnvPolicy;
use agent_undo_domain::esc::display;
use agent_undo_domain::journal::{
    ArgPolicy, CheckpointId, Label, RetentionPolicy, Selector, SessionId,
};
use agent_undo_domain::watch::Debouncer;
use agent_undo_infra::fsutil::{display_path, rel_from_arg};
use agent_undo_infra::layout::{
    DEFAULT_MAX_FILE_SIZE, IN_PROJECT_DIR, StoreDir, external_store_dir, state_base,
};
use agent_undo_infra::project::Project;
use agent_undo_infra::support::NullSink;
use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const HELP: &str = "\
agent-undo - flight recorder and undo for what coding agents do to a project directory

USAGE:
  agent-undo [-C DIR] [--json] <command> [options]

COMMANDS:
  init [--in-project] [--max-file-size SIZE]   create the store and record the baseline
  run [--label L] [--new-session] [--env-allow NAMES]... [--no-log-args] -- CMD...
                                                record what CMD changes as one checkpoint
  checkpoint [--label L] [--new-session]       record the current state manually
  log [--session N]                            list checkpoints
  diff <checkpoint>                            show what a checkpoint changed
  undo <checkpoint> | --last | --session [N] [--apply] [--force]
                                                preview (default) or apply an undo
  restore <path> --from <checkpoint> [--apply] [--force]
                                                restore one path from a checkpoint
  status                                       pending changes since the last checkpoint
  verify                                       re-hash blobs and verify the hash chain
  gc (--keep N | --older-than D) [--apply]     prune old checkpoints and unused blobs
  watch [--interval D] [--quiet D] [--label L] record checkpoints after a quiet period
  doctor                                       environment and store health checks

GLOBAL OPTIONS:
  -C, --project DIR   project directory (default: current directory and its parents)
  --json              machine-readable output (schema version 1)
  -h, --help          show help      -V, --version  show the version

EXIT CODES:
  0 ok   1 failure   2 usage   3 undo/restore refused (conflicts)   4 store locked
  5 verify/doctor found problems   6 not initialized
  run: the command's own exit status (128+N for signal N); 125 agent-undo failed,
       126 cannot execute, 127 not found
";

pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

impl Io<'_> {
    fn outln(&mut self, s: &str) {
        let _ = self.out.write_all(s.as_bytes());
        if !s.ends_with('\n') {
            let _ = self.out.write_all(b"\n");
        }
    }

    fn errln(&mut self, s: &str) {
        let _ = self.err.write_all(s.as_bytes());
        if !s.ends_with('\n') {
            let _ = self.err.write_all(b"\n");
        }
    }

    fn json(&mut self, j: &Json) {
        self.outln(&j.to_compact());
    }
}

fn cwd() -> Result<PathBuf> {
    std::env::current_dir().map_err(|e| Error::io("reading the current directory", e))
}

fn open_project(cli: &Cli) -> Result<Project> {
    let (start, explicit) = match &cli.project {
        Some(p) => (p.clone(), true),
        None => (cwd()?, false),
    };
    let base = state_base().ok();
    let store = StoreDir::locate(&start, explicit, base.as_deref())?;
    Ok(Project::new(store, Box::new(NullSink)))
}

fn label_of(l: Option<Vec<u8>>) -> Result<Option<Label>> {
    l.map(|b| Label::user(b).map_err(Error::from)).transpose()
}

fn id_of(n: u64) -> Result<CheckpointId> {
    Ok(CheckpointId::new(n)?)
}

/// Appends `.agent-undo` to `.git/info/exclude`. Returns a note for the user.
fn add_git_exclude(root: &Path) -> Result<Option<String>> {
    let git = root.join(".git");
    let md = match fs::symlink_metadata(&git) {
        Ok(m) => m,
        Err(_) => {
            return Ok(Some(
                "no .git directory found; make sure the store is never committed".into(),
            ));
        }
    };
    if !md.is_dir() {
        return Ok(Some(".git is not a directory (worktree or submodule); add .agent-undo to its exclude file manually".into()));
    }
    let info = git.join("info");
    fs::create_dir_all(&info).map_err(|e| Error::io("creating .git/info", e))?;
    let exclude = info.join("exclude");
    let current = fs::read_to_string(&exclude).unwrap_or_default();
    if current
        .lines()
        .any(|l| matches!(l.trim(), ".agent-undo" | "/.agent-undo" | ".agent-undo/"))
    {
        return Ok(None);
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&exclude)
        .map_err(|e| Error::io("opening .git/info/exclude", e))?;
    let prefix = if current.is_empty() || current.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    f.write_all(format!("{prefix}{IN_PROJECT_DIR}\n").as_bytes())
        .map_err(|e| Error::io("writing .git/info/exclude", e))?;
    Ok(None)
}

fn cmd_init(
    cli: &Cli,
    io: &mut Io<'_>,
    in_project: bool,
    max: Option<u64>,
    broad: bool,
) -> Result<i32> {
    let start = match &cli.project {
        Some(p) => p.clone(),
        None => cwd()?,
    };
    let root = fs::canonicalize(&start)
        .map_err(|e| Error::io(format!("resolving {}", display_path(&start)), e))?;
    let home = std::env::var_os("HOME").and_then(|h| fs::canonicalize(h).ok());
    if !broad && (root == Path::new("/") || home.as_deref() == Some(root.as_path())) {
        return Err(Error::Usage(
            "refusing to record the filesystem root or your home directory; run init inside a project directory (or pass --allow-broad-root)".into(),
        ));
    }
    let dir = if in_project {
        let d = root.join(IN_PROJECT_DIR);
        if fs::symlink_metadata(&d).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(Error::Unsafe(format!(
                "{} is a symlink; refusing to use it as a store",
                display_path(&d)
            )));
        }
        d
    } else {
        external_store_dir(&state_base()?, &root)
    };
    let store = StoreDir::create(
        &dir,
        &root,
        in_project,
        max.unwrap_or(DEFAULT_MAX_FILE_SIZE),
    )?;
    let note = if in_project {
        add_git_exclude(&root)?
    } else {
        None
    };
    let project = Project::new(store, Box::new(NullSink));
    let base = record_baseline(&project.ports())?;
    let root_s = display_path(&root);
    let store_s = display_path(&project.store.dir);
    if cli.json {
        io.json(
            &envelope("init")
                .with("project", root_s)
                .with("store", store_s)
                .with("in_project", in_project)
                .with("max_file_size", project.store.meta.max_file_size)
                .with("baseline", render::record_json(&base.record, false))
                .with("note", note),
        );
    } else {
        io.out_text(&render::init_text(
            &root_s,
            &store_s,
            &base.record,
            in_project,
        ));
        if let Some(n) = note {
            io.errln(&format!("note: {n}"));
        }
    }
    Ok(exit::OK)
}

impl Io<'_> {
    fn out_text(&mut self, s: &str) {
        let _ = self.out.write_all(s.as_bytes());
    }
}

fn cmd_run(
    cli: &Cli,
    io: &mut Io<'_>,
    label: Option<Vec<u8>>,
    new_session: bool,
    env_allow: &[String],
    no_log_args: bool,
    args: &[Vec<u8>],
) -> i32 {
    let go = || -> std::result::Result<_, RunFailure> {
        let project = open_project(cli)?;
        let env = if env_allow.is_empty() {
            EnvPolicy::Inherit
        } else {
            EnvPolicy::allow(env_allow).map_err(Error::from)?
        };
        let cmd = RunCommand {
            args: args.to_vec(),
            label: label_of(label)?,
            new_session,
            env,
            arg_policy: if no_log_args {
                ArgPolicy::Omit
            } else {
                ArgPolicy::Redact
            },
        };
        run_command(&project.ports(), cmd)
    };
    // The child owns stdout; agent-undo's own report goes to stderr (also in --json mode).
    match go() {
        Ok(rep) => {
            if cli.json {
                let j = envelope("run")
                    .with("checkpoint", render::record_json(&rep.checkpoint, false))
                    .with(
                        "external_checkpoint",
                        rep.external.as_ref().map(|e| render::record_json(e, false)),
                    )
                    .with("exit_status", i64::from(rep.exit.status_code()));
                io.errln(&j.to_compact());
            } else {
                let c = &rep.checkpoint;
                let ext = rep
                    .external
                    .as_ref()
                    .map(|e| format!(" (also recorded {} for changes made outside runs)", e.id))
                    .unwrap_or_default();
                io.errln(&format!(
                    "agent-undo: checkpoint {} (session {}): {}; exit {}{ext}",
                    c.id,
                    c.session,
                    render::counts_text(&c.counts),
                    rep.exit.status_code()
                ));
            }
            rep.exit.status_code()
        }
        Err(f) => {
            let (code, err) = match f {
                RunFailure::NotFound => (
                    exit::RUN_NOT_FOUND,
                    Error::Other(format!(
                        "command not found: {}",
                        args.first().map(|a| display(a)).unwrap_or_default()
                    )),
                ),
                RunFailure::CannotExecute(why) => (
                    exit::RUN_CANNOT_EXEC,
                    Error::Other(format!(
                        "cannot execute the command: {}",
                        display(why.as_bytes())
                    )),
                ),
                RunFailure::NotRecorded {
                    exit: status,
                    error,
                } => {
                    // The command ran: report its own status, not 125, and say plainly
                    // that nothing was recorded for it.
                    let code = status.status_code();
                    if cli.json {
                        io.errln(&render::run_not_recorded_json(&error, code).to_compact());
                    } else {
                        io.errln(&format!(
                            "agent-undo: error: the command exited with status {code} but no checkpoint could be recorded for it: {error}"
                        ));
                    }
                    return code;
                }
                RunFailure::Internal(e) => (exit::RUN_INTERNAL, e),
            };
            if cli.json {
                io.errln(&render::error_json(&err).to_compact());
            } else {
                io.errln(&format!("agent-undo: error: {err}"));
            }
            code
        }
    }
}

fn selector_of(t: &UndoTarget) -> Result<Selector> {
    Ok(match t {
        UndoTarget::Checkpoint(n) => Selector::Checkpoint(id_of(*n)?),
        UndoTarget::Last => Selector::Last,
        UndoTarget::Session(s) => Selector::Session(s.map(SessionId::new).transpose()?),
    })
}

fn print_reversal(
    cli: &Cli,
    io: &mut Io<'_>,
    name: &str,
    plan: &agent_undo_domain::plan::Plan,
    report: Option<&agent_undo_app::usecases::reversal::ReversalReport>,
    apply: bool,
) {
    if cli.json {
        io.json(&render::plan_json(name, plan, report, apply));
    } else {
        io.out_text(&render::plan_text(plan, report, apply));
    }
}

fn reversal_exit(report: &agent_undo_app::usecases::reversal::ReversalReport) -> i32 {
    if report.refused.is_some() {
        exit::REFUSED
    } else if report.error.is_some() {
        exit::FAILURE
    } else {
        exit::OK
    }
}

fn cmd_undo(
    cli: &Cli,
    io: &mut Io<'_>,
    target: &UndoTarget,
    apply: bool,
    force: bool,
) -> Result<i32> {
    let project = open_project(cli)?;
    let ports = project.ports();
    let sel = selector_of(target)?;
    if !apply {
        let plan = plan_undo(&ports, &sel)?;
        print_reversal(cli, io, "undo", &plan, None, false);
        return Ok(if plan.has_conflicts() && !force {
            exit::REFUSED
        } else {
            exit::OK
        });
    }
    let report = apply_undo(&ports, &sel, force)?;
    print_reversal(cli, io, "undo", &report.plan, Some(&report), true);
    Ok(reversal_exit(&report))
}

fn cmd_restore(
    cli: &Cli,
    io: &mut Io<'_>,
    path: &std::ffi::OsStr,
    from: u64,
    apply: bool,
    force: bool,
) -> Result<i32> {
    let project = open_project(cli)?;
    let ports = project.ports();
    let rel = rel_from_arg(&project.store.root, path)?;
    let from = id_of(from)?;
    if !apply {
        let plan = plan_restore(&ports, &rel, from)?;
        print_reversal(cli, io, "restore", &plan, None, false);
        return Ok(if plan.has_conflicts() && !force {
            exit::REFUSED
        } else {
            exit::OK
        });
    }
    let report = apply_restore(&ports, &rel, from, force)?;
    print_reversal(cli, io, "restore", &report.plan, Some(&report), true);
    Ok(reversal_exit(&report))
}

fn cmd_gc(cli: &Cli, io: &mut Io<'_>, policy: &GcPolicy, apply: bool) -> Result<i32> {
    let project = open_project(cli)?;
    let policy = match policy {
        GcPolicy::Keep(n) => RetentionPolicy::keep_last(*n)?,
        GcPolicy::OlderThan(d) => {
            RetentionPolicy::OlderThan(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        }
    };
    let report = gc(&project.ports(), policy, apply)?;
    if cli.json {
        io.json(&render::gc_json(&report));
    } else {
        io.out_text(&render::gc_text(&report));
    }
    Ok(exit::OK)
}

fn cmd_watch(cli: &Cli, io: &mut Io<'_>, w: &WatchOpts) -> Result<i32> {
    let project = open_project(cli)?;
    let ports = project.ports();
    let quiet_ns = i64::try_from(w.quiet.as_nanos()).unwrap_or(i64::MAX);
    let mut deb = Debouncer::new(quiet_ns)?;
    let label = label_of(w.label.clone())?;
    io.errln(&format!(
        "agent-undo: watching {} (poll {:?}, quiet period {:?}); press Ctrl-C to stop",
        display_path(&project.store.root),
        w.interval,
        w.quiet
    ));
    let start = Instant::now();
    let mut commits = 0u64;
    loop {
        let step = watch_tick(&ports, &mut deb, label.as_ref())?;
        if let Some(rec) = step.committed {
            commits += 1;
            if cli.json {
                io.json(&envelope("watch").with("checkpoint", render::record_json(&rec, false)));
            } else {
                io.outln(&format!(
                    "checkpoint {}: {}",
                    rec.id,
                    render::counts_text(&rec.counts)
                ));
            }
            let _ = io.out.flush();
        }
        if w.exit_after.is_some_and(|n| commits >= n)
            || w.timeout.is_some_and(|t| start.elapsed() >= t)
        {
            return Ok(exit::OK);
        }
        std::thread::sleep(w.interval.min(Duration::from_secs(3600)));
    }
}

fn cmd_doctor(cli: &Cli, io: &mut Io<'_>) -> Result<i32> {
    let start = match &cli.project {
        Some(p) => p.clone(),
        None => cwd()?,
    };
    let base = state_base().ok();
    let (root, store) = match StoreDir::locate(&start, cli.project.is_some(), base.as_deref()) {
        Ok(s) => (s.root.clone(), Some(s)),
        Err(Error::NotInitialized(_)) => (
            fs::canonicalize(&start)
                .map_err(|e| Error::io(format!("resolving {}", display_path(&start)), e))?,
            None,
        ),
        Err(e) => return Err(e),
    };
    let checks = run_checks(&root, store.as_ref());
    if cli.json {
        io.json(&doctor_json(&checks));
    } else {
        io.out_text(&doctor_text(&checks));
    }
    Ok(if checks.iter().any(|c| c.status == Status::Fail) {
        exit::INTEGRITY
    } else {
        exit::OK
    })
}

fn execute(cli: &Cli, io: &mut Io<'_>) -> Result<i32> {
    match &cli.command {
        Command::Help(_) => {
            io.out_text(HELP);
            Ok(exit::OK)
        }
        Command::Version => {
            io.outln(&format!("agent-undo {}", env!("CARGO_PKG_VERSION")));
            Ok(exit::OK)
        }
        Command::Init {
            in_project,
            max_file_size,
            allow_broad_root,
        } => cmd_init(cli, io, *in_project, *max_file_size, *allow_broad_root),
        Command::Run { .. } => Err(Error::Other(
            "internal error: run is handled separately".into(),
        )),
        Command::Checkpoint { label, new_session } => {
            let project = open_project(cli)?;
            let out = manual_checkpoint(&project.ports(), label_of(label.clone())?, *new_session)?;
            if cli.json {
                io.json(
                    &envelope("checkpoint")
                        .with("checkpoint", render::record_json(&out.record, false)),
                );
            } else {
                io.outln(&format!(
                    "checkpoint {} recorded (session {}): {}",
                    out.record.id,
                    out.record.session,
                    render::counts_text(&out.record.counts)
                ));
            }
            Ok(exit::OK)
        }
        Command::Log { session } => {
            let project = open_project(cli)?;
            let journal = load_log(&project.ports())?;
            if cli.json {
                io.json(&render::log_json(&journal, *session));
            } else {
                io.out_text(&render::log_text(&journal, *session));
            }
            Ok(exit::OK)
        }
        Command::Diff { checkpoint } => {
            let project = open_project(cli)?;
            let report = diff_checkpoint(&project.ports(), id_of(*checkpoint)?)?;
            if cli.json {
                io.json(&render::diff_json(&report));
            } else {
                io.out_text(&render::diff_text(&report));
            }
            Ok(exit::OK)
        }
        Command::Undo {
            target,
            apply,
            force,
        } => cmd_undo(cli, io, target, *apply, *force),
        Command::Restore {
            path,
            from,
            apply,
            force,
        } => cmd_restore(cli, io, path, *from, *apply, *force),
        Command::Status => {
            let project = open_project(cli)?;
            let rep = status(&project.ports())?;
            let (root, store) = (
                display_path(&project.store.root),
                display_path(&project.store.dir),
            );
            if cli.json {
                io.json(&render::status_json(&root, &store, &rep));
            } else {
                io.out_text(&render::status_text(&root, &store, &rep));
            }
            Ok(exit::OK)
        }
        Command::Verify => {
            let project = open_project(cli)?;
            let rep = verify(&project.ports())?;
            if cli.json {
                io.json(&render::verify_json(&rep));
            } else {
                io.out_text(&render::verify_text(&rep));
            }
            Ok(if rep.ok() { exit::OK } else { exit::INTEGRITY })
        }
        Command::Gc { policy, apply } => cmd_gc(cli, io, policy, *apply),
        Command::Watch(w) => cmd_watch(cli, io, w),
        Command::Doctor => cmd_doctor(cli, io),
    }
}

/// Runs the CLI with the given arguments (without the program name), writing
/// to `out`/`err`. Returns the process exit code.
pub fn main_with(args: Vec<std::ffi::OsString>, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut io = Io { out, err };
    let cli = match crate::args::parse(args) {
        Ok(c) => c,
        Err(e) => {
            io.errln(&format!("agent-undo: {e}"));
            return e.exit_code();
        }
    };
    if let Command::Run {
        label,
        new_session,
        env_allow,
        no_log_args,
        args,
    } = &cli.command
    {
        return cmd_run(
            &cli,
            &mut io,
            label.clone(),
            *new_session,
            env_allow,
            *no_log_args,
            args,
        );
    }
    match execute(&cli, &mut io) {
        Ok(code) => code,
        Err(e) => {
            if cli.json {
                io.json(&render::error_json(&e));
            } else {
                io.errln(&format!(
                    "agent-undo: error: {}",
                    display(e.to_string().as_bytes())
                ));
            }
            e.exit_code()
        }
    }
}

/// Used by tests and the binary to turn raw arguments into `OsString`s.
pub fn os_args(args: &[&str]) -> Vec<std::ffi::OsString> {
    args.iter()
        .map(|a| std::ffi::OsStr::from_bytes(a.as_bytes()).to_os_string())
        .collect()
}
