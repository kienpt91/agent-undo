//! Small adapters: system clock and event sinks.

use agent_undo_app::events::Event;
use agent_undo_app::ports::{Clock, EventSink};
use std::cell::RefCell;

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ns(&self) -> i64 {
        crate::fsutil::now_ns()
    }
}

/// Drops events.
pub struct NullSink;

impl EventSink for NullSink {
    fn publish(&self, _event: Event) {}
}

/// Keeps events in memory so the caller can inspect them after a use case ran.
#[derive(Default)]
pub struct CollectingSink(RefCell<Vec<Event>>);

impl CollectingSink {
    pub fn new() -> CollectingSink {
        CollectingSink::default()
    }

    pub fn take(&self) -> Vec<Event> {
        std::mem::take(&mut self.0.borrow_mut())
    }
}

impl EventSink for CollectingSink {
    fn publish(&self, event: Event) {
        self.0.borrow_mut().push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_undo_domain::journal::ExitInfo;

    #[test]
    fn system_clock_is_recent() {
        assert!(SystemClock.now_ns() > 1_577_836_800_000_000_000);
    }

    #[test]
    fn collecting_sink_keeps_and_drains_events() {
        let s = CollectingSink::new();
        s.publish(Event::CommandFinished {
            exit: ExitInfo::Code(0),
        });
        NullSink.publish(Event::CommandFinished {
            exit: ExitInfo::Code(1),
        });
        assert_eq!(
            s.take(),
            vec![Event::CommandFinished {
                exit: ExitInfo::Code(0)
            }]
        );
        assert!(s.take().is_empty());
    }
}
