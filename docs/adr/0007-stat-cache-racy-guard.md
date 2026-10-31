# 7. Stat cache with a racy-timestamp guard

Status: accepted

Decision: a file is not re-read if size, mtime and ctime equal the previous entry and
both timestamps are older than the previous snapshot's start minus two seconds
(`policy::cache_usable`). ctime cannot be set by user space, so an edit that restores
the old mtime is still seen.

Consequences: large trees are cheap to re-scan; files touched within the margin are
re-hashed, which keeps the result correct on coarse-timestamp filesystems.
