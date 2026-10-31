//! WorkingTree contract: the same suite against the in-memory fake tree and
//! the real directory walker/executor.

#[macro_use]
mod common;

contract_suite!(
    crate::common::fake_tree, crate::common::fs_tree;
    tree_scan_empty_project,
    tree_scan_order_and_kinds,
    tree_scan_hostile_names,
    tree_scan_never_follows_symlinks,
    tree_scan_applies_default_ignores,
    tree_scan_applies_user_ignore_with_negation,
    tree_oversized_ignore_pattern_is_an_error,
    tree_sensitive_files_are_recorded_but_never_stored,
    tree_sensitive_beats_size_cap,
    tree_too_large_file_has_no_blob,
    tree_capture_false_writes_no_blobs,
    tree_scan_stats_and_blob_dedup,
    tree_stat_cache_reuses_unchanged_and_rehashes_modified,
    tree_stat_cache_is_not_used_when_not_allowed,
    tree_stat_cache_does_not_hide_a_missing_blob,
    tree_unlistable_directory_is_carried_forward,
    tree_observe_reports_states,
    tree_observe_refuses_symlinked_and_non_directory_parents,
    tree_apply_write_restores_content_and_mode,
    tree_apply_delete_removes_files_and_symlinks,
    tree_apply_delete_refuses_a_directory,
    tree_apply_mkdir_defers_directory_mode,
    tree_set_dir_mode_refuses_a_file,
    tree_apply_rmdir_skips_non_empty_directories,
    tree_apply_symlink_creates_and_replaces,
    tree_apply_chmod_changes_only_the_mode,
    tree_apply_replace_swaps_directories_and_files,
    tree_apply_refuses_to_leave_the_project,
    tree_planner_blocks_paths_below_symlinks,
    tree_apply_write_with_corrupt_blob_leaves_target_untouched,
    tree_apply_write_with_missing_blob_is_integrity_error,
);
