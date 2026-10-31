//! BlobStore contract: the same suite against the in-memory fake and the
//! filesystem adapter.

#[macro_use]
mod common;

contract_suite!(
    crate::common::fake_blobs, crate::common::fs_blobs;
    blob_put_read_roundtrip,
    blob_read_cap_yields_limit_error,
    blob_missing_is_integrity_error,
    blob_writer_wrong_digest_stores_nothing,
    blob_dropped_writer_stores_nothing,
    blob_multichunk_writer_matches_put,
    blob_hash_stored_equals_digest,
    blob_list_reports_blobs_and_sizes,
    blob_remove_is_idempotent,
    blob_put_is_idempotent_and_deduplicates,
    blob_large_multichunk_roundtrip,
    blob_independent_writers_do_not_interfere,
);
