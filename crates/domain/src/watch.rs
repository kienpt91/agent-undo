//! Quiet-period logic for `watch`: a pending change set is committed only after
//! it stopped changing for a configured period. Time is passed in, so the logic
//! is deterministic and testable with an injected clock.

use crate::error::{DomainError, DomainResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Nothing is pending.
    Idle,
    /// Changes are pending but still settling (`remaining_ns` until the quiet period ends).
    Waiting { remaining_ns: i64 },
    /// The change set was stable for the whole quiet period: record a checkpoint now.
    Commit,
}

#[derive(Debug, Clone)]
pub struct Debouncer {
    quiet_ns: i64,
    pending: Option<(u64, i64)>,
}

impl Debouncer {
    pub fn new(quiet_ns: i64) -> DomainResult<Debouncer> {
        if quiet_ns < 0 {
            return Err(DomainError::Usage(
                "the quiet period must not be negative".into(),
            ));
        }
        Ok(Debouncer {
            quiet_ns,
            pending: None,
        })
    }

    /// Feeds one observation: the fingerprint of the pending change set (`None`
    /// if the tree equals the last checkpoint) at time `now_ns`.
    pub fn observe(&mut self, now_ns: i64, fingerprint: Option<u64>) -> Tick {
        let Some(fp) = fingerprint else {
            self.pending = None;
            return Tick::Idle;
        };
        match self.pending {
            Some((prev_fp, since)) if prev_fp == fp && now_ns >= since => {
                let elapsed = now_ns - since;
                if elapsed >= self.quiet_ns {
                    self.pending = None;
                    Tick::Commit
                } else {
                    Tick::Waiting {
                        remaining_ns: self.quiet_ns - elapsed,
                    }
                }
            }
            _ => {
                // New or changed change set (or the clock went backwards): restart the timer.
                if self.quiet_ns == 0 {
                    self.pending = None;
                    return Tick::Commit;
                }
                self.pending = Some((fp, now_ns));
                Tick::Waiting {
                    remaining_ns: self.quiet_ns,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
}
