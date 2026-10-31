# 10. A hostile tree degrades to warnings, never to a failed checkpoint

Status: accepted

Context: a directory with more than 200,000 entries, nesting deeper than 256 levels or an
oversized `.agent-undoignore` aborted the whole scan. When this happened during `run` the
command had already executed, nothing was recorded, and every later checkpoint failed too.

Decision: caps degrade locally. The directory is recorded, its contents are not, its
previous entries are carried forward unchanged (so no spurious deletions), and a warning is
reported. Ignored names are dropped while listing and do not count against the cap. A bad
ignore file means the default rules plus a warning (only ever more is recorded). A file
that cannot be rewound or read becomes an `unreadable` entry. If the command ran but its
checkpoint cannot be stored, `run` returns the command's own status and says so, instead of
replacing it with 125.

Consequences: recording keeps working under hostile input; a user sees warnings in `run`,
`checkpoint` and `status`, and `--json` carries them as data.
