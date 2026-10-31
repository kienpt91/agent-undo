//! Locker contract: the same suite against the in-memory fake and the
//! `flock` adapter.

#[macro_use]
mod common;

use agent_undo_app::error::Error;
use agent_undo_app::ports::Locker;
use agent_undo_infra::lock::FsLocker;

contract_suite!(
    crate::common::fake_locker, crate::common::fs_locker;
    locker_exclusive_excludes_everything,
    locker_shared_allows_shared_but_excludes_exclusive,
    locker_guard_drop_releases_exclusive,
    locker_last_shared_guard_releases_the_lock,
    locker_refusal_is_the_locked_error_variant,
);

/// Real adapter only: the lock lives in the file, so independent locker
/// instances (as in two processes) exclude each other.
#[test]
fn fs_separate_instances_on_one_path_exclude_each_other() {
    let env = common::fs_locker();
    let other = FsLocker::new(env.lock_path.clone());
    let g = env.exclusive().unwrap();
    assert!(matches!(other.exclusive(), Err(Error::Locked(_))));
    assert!(matches!(other.shared(), Err(Error::Locked(_))));
    drop(g);
    let s1 = env.shared().unwrap();
    let s2 = other.shared().unwrap();
    assert!(matches!(other.exclusive(), Err(Error::Locked(_))));
    drop((s1, s2));
    drop(other.exclusive().unwrap());
}
