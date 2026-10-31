# 3. Sensitive files are classified before any byte is stored

Status: accepted

Context: a store of snapshots would otherwise become a second copy of the user's
secrets.

Decision: every regular file is read twice. Pass 1 hashes and scans it (secret
detectors, names); nothing is written. Only if the file is not sensitive does pass 2
copy it into a blob, re-scanning and re-hashing so the stored bytes are exactly the
classified bytes; a mismatch or a late detection discards the temp blob. Sensitive
files are recorded as size plus HMAC(store key, content hash): the manifest cannot be
used to brute-force the content, yet changes remain visible. Undo never writes or
deletes a sensitive path.

Consequences: detectors are heuristics; what they miss is stored. The default store
location is outside the project with 0700/0600 permissions to limit that exposure.
