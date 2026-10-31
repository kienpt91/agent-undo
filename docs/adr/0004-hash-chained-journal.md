# 4. Append-only, hash-chained journal; one full manifest per checkpoint

Status: accepted

Decision: each checkpoint appends one record that contains the hash of the previous
record and the digests of its manifest and change set. The `Journal` aggregate rebuilds
and verifies the chain on load. `gc` marks checkpoints as pruned instead of rewriting
the log, so the chain stays valid.

Consequences: edits, removals and reordering in the middle are detected; truncating the
tail is not (anyone with write access can also recompute the chain). The head hash is
printed by `log --json` so a wrapper can anchor it elsewhere.
