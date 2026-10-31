# 2. No third-party crates; SHA-256 and HMAC implemented in the domain

Status: accepted

Context: the tool reads untrusted project trees and runs next to coding agents, so its
own supply chain matters. `sha2` and `serde` would add several crates, two with build
scripts.

Decision: the lock file contains only the workspace crates. SHA-256 (FIPS 180-4) and
HMAC-SHA-256 (RFC 2104) are implemented in about 150 lines and checked against the
NIST/RFC 4231 vectors, padding edge cases and every split point of incremental updates.
JSON is only written, never parsed; store formats are line based.

Consequences: no build scripts, nothing to audit but this repository. The hash is
slower than hardware-accelerated crates (no SHA extensions); correctness of the hash is
our responsibility, which is why the vectors are tests and `doctor` runs a known-answer
check.
