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
