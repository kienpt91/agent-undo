//! SnapshotRepository contract: the same suite against the in-memory fake and
//! the filesystem adapter, plus a check that both produce identical digests.

#[macro_use]
mod common;

contract_suite!(
    crate::common::fake_snapshots, crate::common::fs_snapshots;
    snapshot_commit_and_stream_roundtrip,
    snapshot_stored_digests_equal_written,
    snapshot_digests_depend_only_on_their_own_stream,
    snapshot_empty_checkpoint,
    snapshot_out_of_order_entries_are_rejected,
    snapshot_uncommitted_writer_leaves_nothing,
    snapshot_remove_then_open_is_integrity_error,
    snapshot_unknown_checkpoint_is_integrity_error,
    snapshot_list_returns_sorted_ids,
    snapshot_hostile_paths_roundtrip_in_order,
    snapshot_many_entries_stream_back_sorted,
    snapshot_interleaved_writers_are_independent,
);

/// The fake must mirror the real on-disk format: the same logical content
/// yields identical manifest and change-set digests.
#[test]
fn fake_and_fs_digests_are_identical_for_the_same_content() {
    let fake = common::snapshot_scenario_digests(common::fake_snapshots);
    let real = common::snapshot_scenario_digests(common::fs_snapshots);
    assert_eq!(fake.len(), real.len());
    for (i, (f, r)) in fake.iter().zip(&real).enumerate() {
        assert_eq!(f.entries, r.entries, "scenario {i}: entry count");
        assert_eq!(f.manifest, r.manifest, "scenario {i}: manifest digest");
        assert_eq!(f.changes, r.changes, "scenario {i}: changes digest");
    }
}

/// Real adapter only: a discarded writer must not leave temp files behind.
#[test]
fn fs_uncommitted_writer_leaves_no_temp_files() {
    let repo = common::fs_snapshots();
    {
        let mut w = agent_undo_app::ports::SnapshotRepository::begin(&repo, common::id(1)).unwrap();
        w.write_entry(&common::rp("a"), &common::file_entry(b"a", 0o644))
            .unwrap();
    }
    let left: Vec<_> = std::fs::read_dir(&repo.tmp_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "leftover temp files: {left:?}");
}
