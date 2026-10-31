# 11. The store must be private and free of symlinks, and says so when it is not

Status: accepted

Decision: `init` refuses a store directory that is a symlink or contains one. Opening a
store requires: owner equals the effective uid (read without `unsafe` from `/proc/self`, or
from a file the process creates), no group/other permission bits on the store, its files
and its directories, no symlinked store file, and for an external store a parent directory
that others cannot write to unless it is sticky. All store files are opened with
`O_NOFOLLOW`. `doctor` turns a refusal into a failed check.

Consequences: a store prepared by another user or planted with links cannot redirect the
tool's writes or feed it forged manifests. Moving a store by copying it needs `cp -a`
(modes preserved). A project inside a group-writable directory still works for in-project
stores because the parent check applies to external stores only.
