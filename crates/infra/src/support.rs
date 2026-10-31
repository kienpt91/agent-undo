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
mod tests;
