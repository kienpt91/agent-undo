# Security

agent-undo is an example project. It has not been audited and is not known to be used
in production. Treat it accordingly.

## Reporting a vulnerability

Please report privately: use GitHub's private vulnerability reporting on this
repository ("Security" tab, "Report a vulnerability"), or email
kienphan.dev@gmail.com. Do not open a public issue for security problems.
There is no bug bounty and no response-time guarantee.

## Threat model

What the tool is designed to withstand (inputs it does not trust):

* **Hostile project contents.** File names with control characters, ANSI/OSC
  sequences, newlines or bidirectional overrides; symlinks (to files or directories,
  inside or outside the project, swapped in after planning); special files (FIFOs,
  sockets, devices); files that change while being read; huge directories and files.
  Output is escaped, symlinks are recorded and never followed, special files are never
  opened, memory is bounded.
* **A damaged or tampered store.** Every line reader has a maximum line length; every
  path read from the store is validated (`..`, absolute paths and NUL are rejected)
  before it can reach the restore engine; blobs are re-hashed before they are written
  back; the journal is hash-chained and `verify` re-checks everything.
* **Secrets in the project.** Sensitive files are never stored (see README).

What it does **not** defend against:

* A process running as the same user that deliberately attacks the store or races the
  tool: it can read the state directory, delete it, or recompute the hash chain.
  The store is outside the project with 0700/0600 permissions by default to prevent
  accidents, not to stop an adversary with your user id.
* Check/use races on the project directory. Std has no `openat`; restores re-validate
  with `lstat` immediately before each rename, which narrows but does not close the
  window against a concurrent process with write access to the project.
* Secrets the heuristic detectors do not recognise: such a file is stored like any
  other file.
* Truncation of the tail of the log (the chain detects edits, removals and reordering
  in the middle). `log --json` prints the head hash so a wrapper can anchor it.
* Anything outside the project root, `.git` metadata (ignored by design) and
  directories excluded by ignore rules.

## Dependency policy

* The workspace has **no third-party crates**: `Cargo.lock` lists only the four
  workspace crates. SHA-256 and HMAC are implemented in the domain crate and tested
  against the published vectors (see `docs/adr/0002-no-third-party-dependencies.md`).
* Crates with a build script (`build.rs`): **none**. No proc-macro crates either.
* `rust-toolchain.toml` pins Rust 1.95.0; the CI workflow uses only the runner's
  preinstalled rustup and `actions/checkout` pinned to a commit SHA.
* Dependabot is configured for cargo and GitHub Actions with a 7-day cooldown.

## Code policy

* `#![forbid(unsafe_code)]` in every shipped crate. The only `unsafe` in the repository is the
  counting global allocator in `crates/memcheck/tests/memory.rs`; `agent-undo-memcheck` is a
  test-only workspace member that no shipped crate or the binary depends on.
* `unwrap`, `expect`, indexing and `panic!` are denied outside tests in every crate;
  arithmetic that can overflow on untrusted sizes is checked or saturating and
  `overflow-checks` is on in release builds.
* No network access of any kind; the tests need none.
