# 12. Command lines and labels are redacted before they reach the journal

Status: accepted

Context: the journal is append-only, hash-chained and printed by `log`, `diff` and
`run --json`; arguments such as `--token ghp_...` or `DB_PASSWORD=...` would live there
forever.

Decision: `CommandLine::recorded` (domain) redacts with the content detectors plus argv
rules (`--password VALUE`, `--flag=VALUE` for secret-named flags, `NAME_SECRET=value`
words including inside `sh -c` scripts, credential headers) before truncation; `Label::user`
redacts secret-looking labels. `run --no-log-args` records the program name only.

Consequences: logs are less informative where a secret was passed; redaction is heuristic
and a plain-looking secret argument is kept. Redaction is idempotent.
