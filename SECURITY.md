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
  inside or outside the project, swapped in after planning or during a scan); special
  files (FIFOs, sockets, devices); files that change while being read; directories
  with huge numbers of entries or extreme nesting; a malformed or oversized
  `.agent-undoignore`. Output is escaped, symlinks are recorded and never followed,
  special files are never opened, memory is bounded, and one odd entry degrades to a
  warning (`unreadable` entry, or a directory whose contents are not recorded)
  instead of making the whole checkpoint fail.
* **A damaged or tampered store.** Every line reader has a maximum line length; every
  path read from the store is validated (`..`, absolute paths and NUL are rejected)
  before it can reach the restore engine; blobs are re-hashed before they are written
  back; the journal is hash-chained and `verify` re-checks everything.
* **A store someone else prepared.** `init` refuses a store directory that is, or
  contains, a symlink; every command refuses a store that is not owned by the current
  user, has any group or other permission bit, contains a symlinked store file, or (for
  a store outside the project) sits in a directory other users can write to without the
  sticky bit. Store files are opened with `O_NOFOLLOW`. `doctor` reports such a store as
  a failed check instead of crashing.
* **Secrets in the project and on the command line.** Sensitive files are never stored
  (see README); a copy or rename of a secret file stays sensitive because content is
  recognised by a keyed id, not only by name; secrets in the arguments and label of
  `run` are redacted before they are logged.

What it does **not** defend against:

* A process running as the same user that deliberately attacks the store or races the
  tool: it can read the state directory, delete it, or recompute the hash chain.
  The store is outside the project with 0700/0600 permissions by default to prevent
  accidents, not to stop an adversary with your user id.
* Check/use races on the project directory. Std has no `openat`, so the tool cannot
  walk or modify the tree relative to a directory file descriptor. Restores re-validate
  every parent with `lstat` immediately before each rename, and `chmod` goes through a
  descriptor opened with `O_NOFOLLOW`; the scan re-checks the identity of each directory
  after listing it and around each file read, and compares the identity of every opened
  file with its `lstat`. That narrows the windows but does not close them against a
  concurrent process with write access to the project. If agent-undo runs outside the
  sandbox of the agent it records, treat a swapped-symlink race during a *scan* as
  able to read (not write) files the tool's user can read; content that matches the
  secret detectors is still withheld.
* Secrets the heuristic detectors do not recognise: such a file is stored like any
  other file. The detectors are line-oriented and ASCII only; they do not see UTF-16 or
  base64 or compressed copies, nor values split across lines. A secret whose first
  appearance is under an innocent name with undetectable content is stored; if the same
  content is later found under a secret name, newer checkpoints treat it as sensitive but
  the already stored blob remains until `gc` drops the checkpoints that reference it.
* An agent that edits `.agent-undoignore` (it lives in the project): ignored paths are
  not recorded, so changes to them cannot be undone. A malformed ignore file is replaced
  by the default rules with a warning.
* Killing the wrapper. Without `unsafe` or a libc binding there is no signal handling:
  `SIGKILL`, `SIGTERM` or `SIGHUP` sent to `agent-undo run` ends the wrapper while the
  wrapped command may keep running and no checkpoint is recorded for that run. The
  changes are not lost: the next `run`, `checkpoint` or `watch` records everything that
  differs from the last checkpoint (as an `external` checkpoint), and it can be undone.
  `Ctrl-C` in a terminal reaches the wrapper and the command alike.
* `--force`. It is all-or-nothing: it applies every conflicting item, including ones
  that overwrite a `too-large` file whose content is not backed up in the `pre-undo`
  checkpoint. Sensitive, special and blocked items are never applied, with or without it.
* Truncation of the tail of the log (the chain detects edits, removals and reordering
  in the middle). `log --json` prints the head hash so a wrapper can anchor it.
* Anything outside the project root, `.git` metadata (ignored by design) and
  directories excluded by ignore rules.

## Dependency policy

* The workspace has **no third-party crates**: `Cargo.lock` lists only the five
  workspace crates (the four product crates and the test-only `agent-undo-memcheck`). SHA-256 and HMAC are implemented in the domain crate and tested
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
  `overflow-checks` is on in release builds, so an arithmetic overflow aborts the
  process instead of wrapping. Sizes and counters that come from untrusted input are
  saturated or compared before use, but not every counter in the code is checked
  explicitly; overflow was not reachable with the values traced in review.
* Open-flag constants (`O_NOFOLLOW`, `O_NONBLOCK`, `O_DIRECTORY`) are written per
  target (Linux x86_64 and aarch64, macOS) and were read from each platform's C
  library; any other target fails to compile instead of silently losing the protection.
* No network access of any kind; the tests need none.
