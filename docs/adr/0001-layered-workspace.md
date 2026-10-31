# 1. Layered cargo workspace with a compiler-enforced dependency rule

Status: accepted

Context: the first version was one crate where filesystem code, rules and CLI were
interleaved, so rules could only be tested through temp directories.

Decision: four crates, `domain <- app <- infra <- cli`. The domain crate has no
dependencies and performs no IO, clock reads or randomness; time and ids arrive through
ports. The application crate depends only on the domain and defines the ports.
Infrastructure implements the ports; the CLI composes everything. Cargo manifests make
a wrong import a compile error; `crates/cli/tests/architecture.rs` also scans sources
for IO in the pure layers.

Consequences: rules are tested as fast pure tests, use cases with in-memory fakes,
adapters with contract tests, and the CLI end to end.
