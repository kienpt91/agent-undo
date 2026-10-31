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
mod tests;
