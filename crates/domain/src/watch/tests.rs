use super::*;

const S: i64 = 1_000_000_000;

#[test]
fn idle_when_nothing_pending() {
    let mut d = Debouncer::new(2 * S).unwrap();
    assert_eq!(d.observe(0, None), Tick::Idle);
    assert_eq!(d.observe(10 * S, None), Tick::Idle);
}

#[test]
fn commits_only_after_the_quiet_period() {
    let mut d = Debouncer::new(2 * S).unwrap();
    assert_eq!(
        d.observe(0, Some(1)),
        Tick::Waiting {
            remaining_ns: 2 * S
        }
    );
    assert_eq!(d.observe(S, Some(1)), Tick::Waiting { remaining_ns: S });
    assert_eq!(
        d.observe(2 * S - 1, Some(1)),
        Tick::Waiting { remaining_ns: 1 }
    );
    assert_eq!(d.observe(2 * S, Some(1)), Tick::Commit);
}

#[test]
fn further_changes_restart_the_timer() {
    let mut d = Debouncer::new(2 * S).unwrap();
    d.observe(0, Some(1));
    assert_eq!(
        d.observe(S, Some(2)),
        Tick::Waiting {
            remaining_ns: 2 * S
        },
        "fingerprint changed"
    );
    assert_eq!(d.observe(2 * S, Some(2)), Tick::Waiting { remaining_ns: S });
    assert_eq!(d.observe(3 * S, Some(2)), Tick::Commit);
}

#[test]
fn committing_clears_pending_state() {
    let mut d = Debouncer::new(S).unwrap();
    d.observe(0, Some(7));
    assert_eq!(d.observe(S, Some(7)), Tick::Commit);
    // the same fingerprint again is a new pending set
    assert_eq!(d.observe(S + 1, Some(7)), Tick::Waiting { remaining_ns: S });
}

#[test]
fn reverting_the_changes_cancels_the_pending_commit() {
    let mut d = Debouncer::new(2 * S).unwrap();
    d.observe(0, Some(1));
    assert_eq!(d.observe(S, None), Tick::Idle);
    assert_eq!(
        d.observe(3 * S, Some(1)),
        Tick::Waiting {
            remaining_ns: 2 * S
        }
    );
}

#[test]
fn zero_quiet_period_commits_immediately() {
    let mut d = Debouncer::new(0).unwrap();
    assert_eq!(d.observe(5, Some(1)), Tick::Commit);
}

#[test]
fn clock_going_backwards_restarts_the_timer() {
    let mut d = Debouncer::new(2 * S).unwrap();
    d.observe(10 * S, Some(1));
    assert_eq!(
        d.observe(5 * S, Some(1)),
        Tick::Waiting {
            remaining_ns: 2 * S
        }
    );
}

#[test]
fn negative_quiet_period_is_rejected() {
    assert!(Debouncer::new(-1).is_err());
}
