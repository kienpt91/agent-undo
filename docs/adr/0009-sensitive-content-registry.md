# 9. Sensitivity follows content, remembered by keyed id

Status: accepted (supersedes the name-only gate described in ADR 3)

Context: a security review showed that `cp .env settings.txt` made the copy storable:
sensitivity depended on the current path and on an entropy-gated content detector, so a
typical low-entropy value such as `DB_PASSWORD=hunter2` was copied into the blob store
and printed by `diff`.

Decision: three signals decide `policy::classify_file`: the name, the content detectors
(now including `NAME_PASSWORD=value`-style assignments of any entropy) and *known
content*. Every content ever classified as sensitive is remembered as its keyed id
(`HMAC(store key, content hash)`) in `sensitive-ids` in the store (a pure `SensitiveIds`
set in the domain, bounded at 200,000 ids; persistence is an infrastructure detail).
Files are compared against it whatever they are called. Before the main walk, files with
secret names are hashed so a copy that sorts earlier than its original is recognised in the
same scan. A cached entry for content that has become known is not reused. Read-only scans
(`status`, plans) use the registry but never write it.

Consequences: copies and renames stay sensitive and undo leaves them alone. Content stored
before it was ever recognised stays in the older checkpoints until `gc`. The registry holds
only keyed ids, never content or plain hashes. A corrupt or symlinked registry fails the
scan instead of silently forgetting secrets.
