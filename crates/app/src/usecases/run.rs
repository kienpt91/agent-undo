//! `run`: snapshot, execute the wrapped command, snapshot again, record the
//! change set and the exit status as one checkpoint.

use super::record::{CheckpointRequest, record_checkpoint};
use crate::error::Error;
use crate::events::Event;
use crate::ports::{Ports, RunOutcome, RunRequest, ScanStats};
use agent_undo_domain::env::EnvPolicy;
use agent_undo_domain::journal::{CheckpointRecord, CkptKind, CommandLine, ExitInfo, Label};

#[derive(Debug, Clone)]
pub struct RunCommand {
    pub args: Vec<Vec<u8>>,
    pub label: Option<Label>,
    pub new_session: bool,
    pub env: EnvPolicy,
}

#[derive(Debug, Clone)]
pub struct RunReport {
    /// Checkpoint for changes made outside any recorded run (found by the "before" snapshot).
    pub external: Option<CheckpointRecord>,
    pub checkpoint: CheckpointRecord,
    pub exit: ExitInfo,
    pub stats: ScanStats,
}

/// Why a command could not produce a checkpoint.
#[derive(Debug)]
pub enum RunFailure {
    NotFound,
    CannotExecute(String),
    Internal(Error),
}

impl From<Error> for RunFailure {
    fn from(e: Error) -> RunFailure {
        RunFailure::Internal(e)
    }
}

pub fn run_command(
    ports: &Ports<'_>,
    cmd: RunCommand,
) -> std::result::Result<RunReport, RunFailure> {
    if cmd.args.is_empty() {
        return Err(RunFailure::Internal(Error::Usage(
            "run needs a command after `--`".into(),
        )));
    }
    let _guard = ports.locks.exclusive()?;
    let mut journal = ports.journal.load()?;
    if journal.is_empty() {
        return Err(RunFailure::Internal(Error::NotInitialized(
            "the journal has no baseline; run `agent-undo init`".into(),
        )));
    }
    // 1. Anything that changed since the last checkpoint is not the command's doing.
    let mut before = CheckpointRequest::new(CkptKind::External);
    before.skip_if_empty = true;
    before.new_session = cmd.new_session;
    before.label =
        Some(Label::new(b"changes outside recorded runs".to_vec()).map_err(Error::from)?);
    let external = record_checkpoint(ports, &mut journal, before)?;
    let new_session_left = cmd.new_session && external.record.is_none();
    // 2. Run the command.
    let session = journal.next_session(new_session_left);
    let request = RunRequest {
        args: cmd.args.clone(),
        env: cmd.env,
        extra_env: vec![
            ("AGENT_UNDO_ACTIVE".to_string(), b"1".to_vec()),
            (
                "AGENT_UNDO_SESSION".to_string(),
                session.get().to_string().into_bytes(),
            ),
            (
                "AGENT_UNDO_CHECKPOINT".to_string(),
                journal.next_id().get().to_string().into_bytes(),
            ),
        ],
    };
    let exit = match ports.runner.run(&request)? {
        RunOutcome::Exited(e) => e,
        RunOutcome::NotFound => return Err(RunFailure::NotFound),
        RunOutcome::CannotExecute(why) => return Err(RunFailure::CannotExecute(why)),
    };
    ports.events.publish(Event::CommandFinished { exit });
    // 3. Record what the command did.
    let mut after = CheckpointRequest::new(CkptKind::Run);
    after.label = cmd.label;
    after.command = Some(CommandLine::bounded(&cmd.args));
    after.exit = Some(exit);
    after.new_session = new_session_left;
    let out = record_checkpoint(ports, &mut journal, after)?;
    let checkpoint = out
        .record
        .ok_or_else(|| Error::Other("internal error: run checkpoint was not recorded".into()))?;
    Ok(RunReport {
        external: external.record,
        checkpoint,
        exit,
        stats: out.stats,
    })
}
