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
    let c = CommandLine::recorded(&args, ArgPolicy::Redact);
    assert!(c.args().len() < 100);
    assert_eq!(c.args().last().unwrap(), b"...[truncated]");
    let small = vec![b"ls".to_vec()];
    assert_eq!(
        CommandLine::recorded(&small, ArgPolicy::Redact).args(),
        small.as_slice()
    );
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
    n.command = Some(CommandLine::recorded(
        &[
            b"sh".to_vec(),
            b"-c".to_vec(),
            b"echo hi; \x1b[0m\t".to_vec(),
        ],
        ArgPolicy::Redact,
    ));
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
fn next_id_and_next_session_preview_the_following_record() {
    let mut j = Journal::empty();
    assert_eq!((j.next_id().get(), j.next_session(false).get()), (1, 1));
    j.record(nc(CkptKind::Baseline, 1, 0)).unwrap();
    assert_eq!(
        (
            j.next_id().get(),
            j.next_session(false).get(),
            j.next_session(true).get()
        ),
        (2, 1, 2)
    );
    let (rec, _) = j.record(nc(CkptKind::Run, 2, 0)).unwrap();
    assert_eq!(rec.id, CheckpointId::new(2).unwrap());
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

#[test]
fn recorded_command_lines_are_redacted_before_they_reach_the_journal() {
    let token = format!("{}{}", "gh", "p_") + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let args = vec![
        b"deploy".to_vec(),
        b"--password".to_vec(),
        b"hunter2".to_vec(),
        token.clone().into_bytes(),
    ];
    let c = CommandLine::recorded(&args, ArgPolicy::Redact);
    let joined: Vec<u8> = c.args().concat();
    assert!(!joined.windows(7).any(|w| w == b"hunter2"));
    assert!(!joined.windows(token.len()).any(|w| w == token.as_bytes()));
    assert_eq!(c.args().len(), 4);
    assert_eq!(c.args().first(), Some(&b"deploy".to_vec()));
}

#[test]
fn omit_policy_keeps_only_the_program_name() {
    let c = CommandLine::recorded(
        &[b"tool".to_vec(), b"--token".to_vec(), b"x".to_vec()],
        ArgPolicy::Omit,
    );
    assert_eq!(c.args(), &[b"tool".to_vec(), b"[args omitted]".to_vec()]);
    let bare = CommandLine::recorded(&[b"tool".to_vec()], ArgPolicy::Omit);
    assert_eq!(bare.args(), &[b"tool".to_vec()]);
    assert!(
        CommandLine::recorded(&[], ArgPolicy::Omit)
            .args()
            .is_empty()
    );
}

#[test]
fn user_labels_that_look_like_secrets_are_redacted_but_system_labels_are_not() {
    assert_eq!(
        Label::user(b"fix tests".to_vec()).unwrap().as_bytes(),
        b"fix tests"
    );
    assert_eq!(
        Label::user(b"DB_PASSWORD=hunter2".to_vec())
            .unwrap()
            .as_bytes(),
        b"[redacted]"
    );
    assert!(Label::user(vec![b'a'; MAX_LABEL_BYTES + 1]).is_err());
}
