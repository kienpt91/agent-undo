# 8. Ports with in-memory fakes, contract tests and measured coverage

Status: accepted

Decision: every port has an in-memory fake (`agent_undo_app::fakes`) that is a real
implementation of the contract. Each adapter contract suite runs against the fake and
the filesystem adapter, so the fake cannot drift. Unit tests live in `tests.rs` files
next to their module so coverage tooling can exclude test code; coverage is measured
with rustc source-based instrumentation (`-C instrument-coverage`, `llvm-cov`) and
reported per layer in the README together with what is not covered.
