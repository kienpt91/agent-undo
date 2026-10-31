//! JournalRepository contract: the same suite against the in-memory fake and
//! the filesystem adapter.

#[macro_use]
mod common;

use agent_undo_app::error::Error;
use agent_undo_app::ports::JournalRepository;

contract_suite!(
    crate::common::fake_journal, crate::common::fs_journal;
    journal_empty_load_is_empty,
    journal_append_then_load_returns_same_records,
    journal_append_after_load_keeps_chain_valid,
    journal_save_pruned_persists,
    journal_pruning_the_newest_record_is_rejected_on_load,
    journal_tampered_storage_is_detected,
    journal_removed_record_is_detected,
    journal_out_of_sequence_append_is_detected_on_load,
    journal_hostile_text_roundtrips,
);

/// Real adapter only: malformed log text is an integrity problem, never a panic.
#[test]
fn fs_garbage_log_lines_are_integrity_errors() {
    for garbage in ["not a record", "1\t2\t3", "\u{1b}[31m\t\t\t", "x\ty\n\n\n"] {
        let repo = common::fs_journal();
        let rec = {
            let mut j = agent_undo_domain::journal::Journal::empty();
            j.record(agent_undo_domain::journal::NewCheckpoint::new(
                agent_undo_domain::journal::CkptKind::Baseline,
                1,
                [1; 32],
                [2; 32],
                agent_undo_domain::change::Counts::default(),
                0,
            ))
            .unwrap()
            .0
        };
        repo.append(&rec).unwrap();
        repo.append_raw_line(garbage);
        let e = match repo.load() {
            Err(e) => e,
            Ok(_) => panic!("garbage line {garbage:?} was accepted"),
        };
        assert!(matches!(e, Error::Integrity(_)), "{garbage:?}: {e}");
    }
}

/// Real adapter only: invalid UTF-8 in the log is an integrity problem.
#[test]
fn fs_non_utf8_log_is_an_integrity_error() {
    let repo = common::fs_journal();
    std::fs::write(&repo.log, [0xffu8, 0xfe, b'\n']).unwrap();
    assert!(matches!(
        match repo.load() {
            Err(e) => e,
            Ok(_) => panic!("accepted"),
        },
        Error::Integrity(_)
    ));
}
