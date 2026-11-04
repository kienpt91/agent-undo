# agent-undo

A flight recorder and undo for what coding agents do to a project directory. It wraps any
command, records exactly which files that command changed, and rolls a step or a whole
session back safely. It works with any agent because it observes the filesystem, not the
agent.

**Status: an example and educational project.** It has not been audited, has no users
that I know of, and makes no claim to be production ready. It is a Rust portfolio piece:
bounded memory, deterministic behavior, a layered design and a lot of tests. Limitations
are listed plainly below.

## What it does

```text
agent-undo init                      # create the store, record the baseline
agent-undo run -- <agent command>    # snapshot, run, snapshot, record one checkpoint
agent-undo log                       # what happened, step by step
agent-undo diff 3                    # what checkpoint #3 changed
agent-undo undo 3                    # preview (nothing is changed)
agent-undo undo 3 --apply            # roll it back; the undo is itself undoable
```

* **Content-addressed snapshots.** SHA-256 blob store, one manifest per checkpoint
  (path -> blob, mode, size, mtime, kind), deduplicated. Files above a configurable cap
  (default 25 MiB) are recorded by hash only (`too-large`) and cannot be restored.
* **Secrets are not copied (best effort).** `.env*`, `*.pem`, `*.key`, `*.p8`, `*.gpg`,
  `id_rsa*`, `id_ed25519*`, `.npmrc`, `.netrc`, `.vault-token`, shell and database
  histories, anything under `.aws/`, `.ssh/`, `.gnupg/`, keystores, credentials files,
  and any file whose *content* matches a secret detector (private key headers, common API
  key shapes, JWTs, credentials in URLs, `NAME_PASSWORD=value`-style assignments, and
  high-entropy values assigned to secret-like names) are recorded as `sensitive`: path,
  size and a keyed hash of the hash only. Their bytes are never written to the store and
  undo reports them as *not restorable by design*. A **copy or rename** of a secret file
  stays sensitive: the store remembers the keyed ids of every sensitive content and
  checks each file it reads against them, whatever the file is called now. The detectors
  are heuristics (line-oriented, ASCII only); see "Security model" for what they miss.
* **Safe undo.** Plan first; refuse if something other than the recorded change touched
  a path (conflict) unless `--force`; save the current state as a `pre-undo` checkpoint
  before changing anything; never leave the project root; do not follow symlinks (parents are re-checked with
  `lstat`, modes are changed through a descriptor opened with `O_NOFOLLOW`); write files
  through temp file plus `rename`; re-validate every path right before touching it.
* **Tamper-evident history.** The checkpoint log is hash-chained; `verify` re-hashes every
  blob and re-checks the chain.
* **Single binary, no dependencies.** `cargo build --release` produces one executable;
  the lock file contains only this workspace's crates (no third-party code, no build
  scripts).

## Build and run

```sh
cargo build --release          # Rust 1.95, pinned in rust-toolchain.toml
target/release/agent-undo --help
```

The binary links the platform's C library dynamically (the Rust default); a fully static
build is possible with a musl target if you have it installed, but is not part of the
checks here. Supported targets: Linux (x86_64, aarch64) and macOS. The `open(2)` flag
values that keep the tool from following symlinks are defined per target and were read
from each platform's C library; any other target fails to compile instead of silently
losing that protection.

Everything in this repository is developed and tested inside a throwaway container:

```sh
scripts/dev.sh 'cargo build --release'     # any cargo command, in the container
scripts/dev.sh scripts/layers.sh           # the test suites, layer by layer
scripts/dev.sh scripts/coverage.sh         # coverage report (numbers below)
scripts/dev.sh 'cargo build --release && AU=/target/release/agent-undo scripts/demo.sh'
```

## Demo

The scripted run below is `scripts/demo.sh`: a fake project, a scripted "agent" (a shell
script that edits and deletes files, creates a directory, changes a mode and rewrites a
fake `.env`), then `log`, `diff`, `undo` as a preview, `undo --apply`, `verify`, and
undoing the undo. Real output; timestamps and the temp directory name vary per run.

```text
$ agent-undo init
initialized agent-undo for /tmp/demo/shop
store: /tmp/demo/state/agent-undo/a74bcd101fa07627
baseline: checkpoint #1 (6 entries)

$ agent-undo run --label "fake agent" -- sh agent.sh
agent-undo: checkpoint #2 (session 1): 2 created, 2 modified, 1 deleted, 1 mode-changed; exit 0

$ agent-undo log
ID    SESSION  KIND       TIME (UTC)            CHANGES               EXIT    LABEL / COMMAND
#1    1        baseline   2026-10-31T06:40:57Z +6 ~0 -0 m0           -       baseline
#2    1        run        2026-10-31T06:40:57Z +2 ~2 -1 m1           0       fake agent: sh ./agent.sh

$ agent-undo diff 2
checkpoint #2 (run, session 1) 2026-10-31T06:40:57Z  exit 0
label: fake agent
command: sh ./agent.sh
changes: 2 created, 2 modified, 1 deleted, 1 mode-changed
M  .env  (sensitive 0644 33 B)
    (sensitive file: content is never stored or shown)
T  agent.sh  (mode 0644 -> 0755)
A  docs  (dir 0755)
A  docs/plan.md  (file 0644 27 B)
--- /dev/null
+++ b/docs/plan.md
@@ -0,0 +1,2 @@
+# Plan
+1. rewrite checkout
M  src/main.rs
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,3 +1,3 @@
 fn main() {
-    println!("checkout v1");
+    println!("checkout v2 (agent was here)");
 }
D  src/pricing.rs
--- a/src/pricing.rs
+++ /dev/null
@@ -1,3 +0,0 @@
-pub fn total(cents: &[u64]) -> u64 {
-    cents.iter().sum()
-}

$ agent-undo undo 2        # dry run: nothing is changed
undo checkpoint #2 (dry run - nothing was changed; re-run with --apply to apply)
  none     .env  [not restorable: sensitive file: not restorable by design (content is never stored)]
  chmod    agent.sh  [ready]
  rmdir    docs  [ready]
  delete   docs/plan.md  [ready]
  write    src/main.rs  [ready]
  write    src/pricing.rs  [ready]
summary: 5 ready, 0 conflicts, 0 already done, 1 not restorable, 0 blocked

$ agent-undo undo 2 --apply
undo checkpoint #2 (applied)
  none     .env  [skipped: sensitive file: not restorable by design (content is never stored)]
  chmod    agent.sh  [applied]
  rmdir    docs  [applied]
  delete   docs/plan.md  [applied]
  write    src/main.rs  [applied]
  write    src/pricing.rs  [applied]
summary: 5 ready, 0 conflicts, 0 already done, 1 not restorable, 0 blocked
saved current state as #3 (pre-undo)
recorded undo as checkpoint #4; 5 applied, 1 skipped. Undo this with: agent-undo undo 4 --apply

$ agent-undo verify
verify: ok - 4 checkpoints checked (0 pruned), 6 blobs checked (0 unreferenced)

$ cat src/main.rs; ls src docs; cat .env
fn main() {
    println!("checkout v1");
}
main.rs
pricing.rs
ls: cannot access 'docs': No such file or directory
DB_PASSWORD=changed-by-the-agent

$ agent-undo log
ID    SESSION  KIND       TIME (UTC)            CHANGES               EXIT    LABEL / COMMAND
#1    1        baseline   2026-10-31T06:40:57Z +6 ~0 -0 m0           -       baseline
#2    1        run        2026-10-31T06:40:57Z +2 ~2 -1 m1           0       fake agent: sh ./agent.sh
#3    1        pre-undo   2026-10-31T06:40:57Z +0 ~0 -0 m0           -       before: undo checkpoint #2
#4    1        undo       2026-10-31T06:40:57Z +1 ~1 -2 m1           -       undo checkpoint #2

$ agent-undo undo --last --apply     # undo the undo
undo checkpoint #4 (applied)
  chmod    agent.sh  [applied]
  mkdir    docs  [applied]
  write    docs/plan.md  [applied]
  write    src/main.rs  [applied]
  delete   src/pricing.rs  [applied]
summary: 5 ready, 0 conflicts, 0 already done, 0 not restorable, 0 blocked
saved current state as #5 (pre-undo)
recorded undo as checkpoint #6; 5 applied, 0 skipped. Undo this with: agent-undo undo 6 --apply

$ agent-undo verify
verify: ok - 6 checkpoints checked (0 pruned), 6 blobs checked (0 unreferenced)
```

Things to notice: the rewritten `.env` is shown as `sensitive` (its content is never
stored or printed) and stays as the agent left it when the undo runs ("not restorable by
design"); the empty directory the agent created is removed after its file; the undo
produced a `pre-undo` checkpoint (#3) and an `undo` checkpoint (#4), so `undo --last`
could bring the agent's changes back.

## Commands

```text
agent-undo - flight recorder and undo for what coding agents do to a project directory

USAGE:
  agent-undo [-C DIR] [--json] <command> [options]

COMMANDS:
  init [--in-project] [--max-file-size SIZE]   create the store and record the baseline
  run [--label L] [--new-session] [--env-allow NAMES]... [--no-log-args] -- CMD...
                                                record what CMD changes as one checkpoint
  checkpoint [--label L] [--new-session]       record the current state manually
  log [--session N]                            list checkpoints
  diff <checkpoint>                            show what a checkpoint changed
  undo <checkpoint> | --last | --session [N] [--apply] [--force]
                                                preview (default) or apply an undo
  restore <path> --from <checkpoint> [--apply] [--force]
                                                restore one path from a checkpoint
  status                                       pending changes since the last checkpoint
  verify                                       re-hash blobs and verify the hash chain
  gc (--keep N | --older-than D) [--apply]     prune old checkpoints and unused blobs
  watch [--interval D] [--quiet D] [--label L] record checkpoints after a quiet period
  doctor                                       environment and store health checks

GLOBAL OPTIONS:
  -C, --project DIR   project directory (default: current directory and its parents)
  --json              machine-readable output (schema version 1)
  -h, --help          show help      -V, --version  show the version

EXIT CODES:
  0 ok   1 failure   2 usage   3 undo/restore refused (conflicts)   4 store locked
  5 verify/doctor found problems   6 not initialized
  run: the command's own exit status (128+N for signal N); 125 agent-undo failed before
       the command started, 126 cannot execute, 127 not found. If the command ran but its
       checkpoint could not be recorded, its own status is returned and stderr says so.
```

* `undo` and `restore` are previews unless `--apply` is given. `undo` takes exactly one of
  `<checkpoint>`, `--last` (newest checkpoint that recorded changes, excluding the baseline
  and `pre-undo` snapshots) or `--session [N]`. A preview that would be refused exits 3.
* `gc` is a preview unless `--apply` is given. It never prunes the newest checkpoint and
  deletes blobs no remaining checkpoint references. Pruned checkpoints stay in the log
  (the chain stays valid) but cannot be undone or diffed.
* `run` starts the command with the project root as its working directory and inherited
  stdio. Environment policy: the parent environment is inherited by default;
  `--env-allow A,B` (repeatable) passes *only* those variables. In both modes
  `AGENT_UNDO_ACTIVE=1`, `AGENT_UNDO_SESSION` and `AGENT_UNDO_CHECKPOINT` are added.
  Program names are looked up in the parent's `PATH`; a relative program path (`./tool`)
  and relative `PATH` entries are resolved against the directory you ran `agent-undo` in
  (not the project root) and handed to `exec` as an absolute path. Relative *arguments*
  are interpreted by the command in the project root. The report goes to stderr so the
  command's stdout is untouched, together with up to five scan warnings.
  The recorded command line has secrets redacted (`--password VALUE`, `--token=VALUE`,
  `NAME_SECRET=value` words, `Authorization:` headers, token shapes); `--no-log-args`
  records only the program name. Labels that look like secrets are redacted too.
  Killing the wrapper (`SIGKILL`/`SIGTERM`/`SIGHUP`) cannot be handled without `unsafe`:
  the command may keep running and no checkpoint is recorded for that run, but the next
  `run`, `checkpoint` or `watch` records its changes as an `external` checkpoint.
* `watch` polls (no OS watcher): every `--interval` it compares the tree with the last
  checkpoint and records a `watch` checkpoint once the change set has been stable for
  `--quiet`. The quiet-period logic is a pure function of injected time and is tested
  with a fake clock.
* `init --in-project` keeps the store in `.agent-undo/` and appends it to
  `.git/info/exclude`. The default is `$XDG_STATE_HOME/agent-undo/<project-id>` (fallback
  `~/.local/state`), directories `0700`, files `0600`.
* Ignored by default: `.git`, `node_modules`, `target`, `.next`, `.nuxt`, `dist`,
  `__pycache__`, `.venv`, `venv`, `.cache` and similar caches, `.DS_Store`.
  `.agent-undoignore` (gitignore-style subset: `*`, `?`, `[a-z]`, `**`, `!`, anchoring,
  trailing `/`; matched without regular expressions in polynomial time) adds patterns and
  can re-include defaults with `!dist/`. The file lives in the project, so an agent can
  edit it; a malformed or oversized one is replaced by the defaults with a warning. Git operations are therefore not recorded or
  undone.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | failure (I/O error, corrupt data, ...) |
| 2 | usage error |
| 3 | `undo`/`restore` refused or would be refused (conflicts); nothing was changed |
| 4 | another agent-undo operation holds the store lock |
| 5 | `verify` or `doctor` found problems |
| 6 | no store for this project (`init` first) |
| `run` | the command's own status (128+N for signal N); 125 agent-undo failed, 126 cannot execute, 127 not found |

### Using it from an agent wrapper (`--json`)

Every command accepts `--json` and prints one line: `{"schema":1,"ok":true,"command":"..."}`
plus command-specific fields; errors are `{"schema":1,"ok":false,"error":{"code":"...","message":"..."}}`
with a stable `code` (`usage`, `refused`, `locked`, `integrity`, `not_initialized`,
`already_initialized`, `unsafe_path`, `limit`, `format`, `io`, `error`). Paths appear as
`path` (escaped for display) and `path_pct` (percent-encoded, exact bytes). `run --json`
writes its JSON to **stderr** because the wrapped command owns stdout.

```sh
# before handing the project to an agent
agent-undo --json run --label "task 42" -- my-agent --task 42 2> run.json
# the last line of run.json has the checkpoint id, counts and exit status
agent-undo --json undo --last            # preview as JSON (items, statuses, reasons)
agent-undo --json undo --last --apply    # apply; exit 3 means conflicts, nothing changed
agent-undo --json log | tail -1          # includes head_hash: anchor it elsewhere to detect log truncation
```

## Security model, honestly

* The store is outside the project by default so an agent working in the project does
  not stumble over it. That prevents accidents; it is not a boundary against a process
  running as your user, which can read the state directory.
* Output escaping covers every path, link target, label and command line: control
  characters, ANSI/OSC sequences, line breaks and bidirectional overrides are escaped.
  Diffs never print the content of files recorded as sensitive.
* Symlinks are recorded as links and not followed. Files are opened with `O_NOFOLLOW` and
  an `fstat` identity check; a scan re-checks each directory's identity after listing it
  and around each file read; undo re-validates the whole parent chain with `lstat`
  immediately before each rename and changes modes through a no-follow descriptor.
  **Rust's standard library has no `openat`, so a concurrent process with write access
  to the project can still race the gap between a check and the following operation.**
  The windows are narrowed, not closed (details in `SECURITY.md`).
* The store is refused unless it is owned by you, has no group/other permission bits and
  contains no symlinked store files; `init` refuses planted symlinks.
* The detectors are heuristics written for this project and tested with fixtures built at
  runtime. They reduce the chance of storing a secret; they do not guarantee it. They are
  line-oriented and ASCII only (UTF-16, base64 or compressed copies and values split over
  several lines are not seen), and a secret first seen under an innocent name with
  undetectable content is stored until the same content shows up under a secret name.
* A hostile tree cannot stop recording: unreadable files, directories with more than
  200,000 entries, nesting deeper than 256 levels and a malformed `.agent-undoignore`
  degrade to warnings (and, for the two caps, to a directory whose contents are not
  recorded) instead of failing the checkpoint.
* `--force` is all-or-nothing and can overwrite a `too-large` file whose content is not
  backed up anywhere; it never applies sensitive, special or blocked items.
* `SECURITY.md` has the threat model, the reporting address and the dependency policy.

### What Rust does and does not give you here

Rust prevents memory-unsafety (no `unsafe` in any shipped crate; `#![forbid(unsafe_code)]`).
It does **not** prevent logic bugs, deadlocks, races on the filesystem, or unbounded
growth. Those are handled by design and by tests: fixed-size read buffers, bounded line
readers, caps on directory entries, plan sizes and diff sizes, checked arithmetic with
`overflow-checks` on in release builds, no `unwrap`/`expect`/indexing outside tests
(lint-enforced), and a test that measures memory.

Memory is measured, not assumed: `crates/memcheck/tests/memory.rs` installs a counting
global allocator (the only `unsafe` in the repository; it lives in a test-only crate that
nothing depends on), builds a tree of 3000 small files plus three 12 MiB files, and checks
that the peak extra allocation of a checkpoint, a `verify` and an undo stays below 8 MiB
(file data is 36 MiB) and that live bytes do not grow across five iterations.

## Architecture

Domain-driven layers as separate crates, so the compiler enforces the dependency rule
(`domain <- app <- infra <- cli`):

| Crate | Layer | Contents |
|---|---|---|
| `crates/domain` | pure domain, std only, no IO/clock/randomness | `RelPath`, `Entry`, `Change`, `Journal` aggregate, undo planning rules, secret detectors, ignore matcher, SHA-256/HMAC, text diff, debouncer |
| `crates/app` | application | use cases (record, run, undo, restore, verify, gc, status, watch, diff), port traits, in-memory fakes |
| `crates/infra` | adapters | filesystem store, blob store, working tree walker and safe applier, flock locker, process runner |
| `crates/cli` | interface | argument parser, renderers, command handlers, the `agent-undo` binary |
| `crates/memcheck` | test-only | counting allocator memory proof |

See [docs/domain.md](docs/domain.md) for the glossary and context map and
[docs/adr](docs/adr) for the decisions.

## Tests and coverage

Tests are organized by layer; every layer runs against what it should, not against mocks
of itself:

| Layer | Kind | Tests |
|---|---|---|
| domain | pure unit and property-style tests (invariants, state transitions, events, redaction, detectors) | 218 |
| application | use cases against in-memory fakes, asserting state and emitted events | 338 |
| infrastructure | contract tests, each suite run against the fake **and** the filesystem adapter (167); unit tests (61); real-filesystem security and hardening tests (39) | 267 |
| architecture | dependency rule, no IO in pure layers, no build scripts | 10 |
| command line | argument/render unit tests (38) and end-to-end tests of the real binary (171) | 209 |
| memory | counting allocator proof | 1 |

Run them with `scripts/dev.sh scripts/layers.sh`. No test needs network access, and all
file activity is inside temp directories.

Line coverage measured with rustc's source-based instrumentation (`-C instrument-coverage`
and `llvm-cov` from the official `llvm-tools-preview` component), test code excluded, by
`scripts/dev.sh scripts/coverage.sh`:

```text
Line coverage by layer (llvm-cov; unit and integration test code excluded)
domain         2888 lines     71 missed   97.54%
app             869 lines     33 missed   96.20%
infra          1953 lines    231 missed   88.17%
cli            1736 lines     88 missed   94.93%
app-fakes       795 lines     32 missed   95.97%
overall        7446 lines    423 missed   94.32%   (all layers, fakes excluded)

Files below 90% line coverage (fakes excluded):
  infra/src/fs_sensitive.rs                        81.4% (11 of 59 lines missed)
  infra/src/fs_tree.rs                             84.3% (105 of 668 lines missed)
  infra/src/fs_blobs.rs                            88.4% (16 of 138 lines missed)
  domain/src/error.rs                              55.6% (4 of 9 lines missed)
  cli/src/doctor.rs                                85.0% (34 of 227 lines missed)
  infra/src/fsutil.rs                              86.8% (27 of 204 lines missed)
  app/src/usecases/verify.rs                       89.6% (12 of 115 lines missed)
```

Uncovered areas, not padded: error branches that need a failing disk (`fs_tree`,
`fs_blobs`, `fs_sensitive`, `fsutil`: I/O errors in the middle of a read, write or
rename), the special-file and cross-device branches of the walker, the macOS-only
branch of `effective_uid`, parts of `doctor` that depend on the host (root user, coarse
timestamps), and a few defensive branches in `verify` that need the store to fail while it
is being listed. The
files below 90% are listed in the table output above. The fakes in `crates/app/src/fakes.rs`
are test support and are reported on their own line, not counted in the layers.

## Limitations

* Only the project directory is observed. Anything an agent does elsewhere (other
  directories, databases, network calls, git history) is not recorded and cannot be undone.
* `.git` is ignored on purpose; undo does not rewind commits or branches.
* Files over the size cap and sensitive files cannot be restored. Special files are never
  touched. Hard links are restored as separate files; owners and extended attributes are
  not recorded; setuid/setgid/sticky bits are not restored.
* A process that races the tool inside the project can exploit the check/use window
  described above.
* Blobs, manifests, change sets and the log are `fsync`ed before they are renamed or
  appended; directory entries are synced best effort, so a power loss can still leave a
  checkpoint whose newest blobs are missing, which `verify` reports.
* `watch` stops on Ctrl-C without cleanup; interrupted writes leave temp files that
  `doctor` reports and `gc --apply` removes.
* The hash is a small portable implementation checked against the standard vectors, not
  a hardware-accelerated one: large first snapshots are CPU-bound.

## Secrets and hooks

Never commit `.env` files or credentials. Keep real values in a local, ignored `.env` and commit only a `.env.example` with placeholders; `.gitignore` already blocks common secret-like files.

Install [lefthook](https://github.com/evilmartians/lefthook) and run `lefthook install` once per clone. This enables two hooks:

- `pre-commit` runs `sh scripts/secret-scan.sh --staged` on what you are about to commit.
- `pre-push` runs `sh scripts/secret-scan.sh --tree` on the whole working tree.

CI additionally scans the full history. The scanner is a dependency-free shell script that looks for forbidden file names and key-shaped values, and it never prints the matched value. A reviewed false positive can be allowed in `.secret-scan-allow` with one line per file and rule (`<path> <rule>   # reason`), or on a single line with an inline `secret-scan: allow` marker.

If a secret is ever committed, rotate it first (treat it as compromised), then remove it from history.

## Releasing

Releases are cut by pushing a `vMAJOR.MINOR.PATCH` tag. The `release` workflow then verifies the code, builds the files, writes `SHA256SUMS`, attests where they were built and creates the GitHub release. See [RELEASING.md](RELEASING.md) for how to cut a release and how to verify a download with `gh attestation verify`.

## License

MIT, see [LICENSE](LICENSE).
