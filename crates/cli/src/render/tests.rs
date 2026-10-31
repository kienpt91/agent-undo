use super::*;
use agent_undo_domain::hash::sha256;
use agent_undo_domain::journal::{ArgPolicy, CkptKind, CommandLine, Label, NewCheckpoint};

fn journal() -> Journal {
    let mut j = Journal::empty();
    j.record(NewCheckpoint::new(
        CkptKind::Baseline,
        1_700_000_000_000_000_000,
        sha256(b"m"),
        sha256(b"c"),
        Counts::default(),
        2,
    ))
    .unwrap();
    let mut n = NewCheckpoint::new(
        CkptKind::Run,
        1_700_000_100_000_000_000,
        sha256(b"m2"),
        sha256(b"c2"),
        Counts {
            created: 1,
            modified: 2,
            deleted: 3,
            mode_changed: 0,
        },
        5,
    );
    n.label = Some(Label::new(b"fix \x1b[31mtests".to_vec()).unwrap());
    n.command = Some(CommandLine::recorded(
        &[b"sh".to_vec(), b"-c".to_vec(), b"echo \x07hi".to_vec()],
        ArgPolicy::Redact,
    ));
    n.exit = Some(ExitInfo::Code(3));
    j.record(n).unwrap();
    j
}

#[test]
fn log_text_escapes_hostile_label_and_command() {
    let text = log_text(&journal(), None);
    assert!(!text.contains('\x1b') && !text.contains('\x07'));
    assert!(text.contains("fix \\x1b[31mtests"));
    assert!(text.contains("+1 ~2 -3 m0"));
    assert!(text.contains("2023-11-14T22:13:20Z"));
}

#[test]
fn log_text_filters_by_session() {
    let text = log_text(&journal(), Some(9));
    assert_eq!(text.lines().count(), 1, "only the header remains");
}

#[test]
fn log_json_is_stable_and_single_line() {
    let j = log_json(&journal(), None).to_compact();
    assert!(!j.contains('\n'));
    assert!(j.starts_with("{\"schema\":1,\"ok\":true,\"command\":\"log\",\"checkpoints\":["));
    assert!(j.contains("\"kind\":\"baseline\""));
    assert!(j.contains("\"exit\":{\"code\":3}"));
    assert!(j.contains("\"head_hash\":\""));
    assert!(!j.contains('\x1b'));
}

#[test]
fn error_json_shape() {
    let j = error_json(&Error::Refused("nope \x1b".into())).to_compact();
    assert_eq!(
        j,
        "{\"schema\":1,\"ok\":false,\"error\":{\"code\":\"refused\",\"message\":\"nope \\\\x1b\"}}"
    );
}

#[test]
fn entry_json_never_exposes_the_sensitive_id() {
    let e = Entry::hashed(Kind::Sensitive, &sha256(b"s"), 0o600, 5, 0, 0).unwrap();
    let j = entry_json(&e).to_compact();
    assert!(j.contains("\"sensitive\":true"));
    assert!(!j.contains(&to_hex(&e.digest().unwrap())));
    let f = Entry::hashed(Kind::File, &sha256(b"s"), 0o644, 5, 0, 0).unwrap();
    assert!(entry_json(&f).to_compact().contains(&to_hex(&sha256(b"s"))));
    let l = Entry::symlink(b"t\x1b".to_vec(), 0, 0).unwrap();
    assert!(!entry_json(&l).to_compact().contains('\x1b'));
}

#[test]
fn counts_helpers() {
    let c = Counts {
        created: 1,
        modified: 2,
        deleted: 3,
        mode_changed: 4,
    };
    assert_eq!(
        counts_text(&c),
        "1 created, 2 modified, 3 deleted, 4 mode-changed"
    );
    assert!(counts_json(&c).to_compact().contains("\"total\":10"));
}

#[test]
fn init_text_mentions_the_baseline() {
    let j = journal();
    let t = init_text("/p", "/s", &j.records()[0], true);
    assert!(t.contains("baseline: checkpoint #1") && t.contains("inside the project"));
}

#[test]
fn verify_and_gc_text() {
    let r = VerifyReport {
        problems: vec!["blob xyz is corrupt".into()],
        warnings: vec!["stray".into()],
        ..VerifyReport::default()
    };
    let t = verify_text(&r);
    assert!(
        t.contains("PROBLEM: blob xyz is corrupt")
            && t.contains("FAILED")
            && t.contains("warning: stray")
    );
    assert!(verify_text(&VerifyReport::default()).contains("verify: ok"));
    assert!(verify_json(&r).to_compact().contains("\"verified\":false"));
    let g = GcReport::default();
    assert!(gc_text(&g).contains("dry run") && gc_text(&g).contains("--apply"));
    assert!(gc_json(&g).to_compact().contains("\"applied\":false"));
}
