# 6. The store lives outside the project by default

Status: accepted

Decision: `$XDG_STATE_HOME/agent-undo/<project-id>` (fallback `~/.local/state`), mode
0700. `init --in-project` is available and appends the store to `.git/info/exclude`.
An agent working inside the project cannot casually read or edit its own recorder.

Consequences: not a security boundary against an agent running as the same user, which
can read the state directory too; it prevents accidents and commits of the store.
