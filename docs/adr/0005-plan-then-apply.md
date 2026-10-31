# 5. Undo is plan, refuse, pre-undo snapshot, apply with re-validation

Status: accepted

Decision: a reversal first builds a plan (target, expected, current per path). Any
conflict refuses the whole apply unless `--force`. Before the first change a `pre-undo`
checkpoint saves the current state, and the result is recorded as its own checkpoint so
an undo can be undone. Immediately before each item the use case re-observes the path
and fails if it differs from the plan; adapters re-check every parent directory with
`lstat` before each rename.

Consequences: Rust's std has no `openat`, so a process that races the tool inside the
project can still win a check/use window. The checks narrow it; the README states the
limit.
