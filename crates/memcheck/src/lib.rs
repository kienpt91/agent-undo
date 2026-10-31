//! Test-only crate. The memory-bound tests live in `tests/memory.rs` because
//! they need a counting global allocator, which requires `unsafe`; the workspace
//! forbids `unsafe` everywhere else. Nothing here is linked into `agent-undo`.
#![forbid(unsafe_code)]
