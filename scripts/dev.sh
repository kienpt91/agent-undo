#!/bin/sh
# Runs a command in a throwaway container with the repository mounted.
#   scripts/dev.sh 'cargo test --workspace'
# The container runs as your user with all capabilities dropped and no network
# (the workspace has no third-party dependencies, so nothing needs fetching).
# Cargo's target directory lives in a docker volume, not in the repository.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
image=${AGENT_UNDO_DEV_IMAGE:-agent-undo-dev:1.95}
if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker build -q -t "$image" -f "$repo/docker/Dockerfile" "$repo/docker" >/dev/null
fi
vol=agent-undo-target
docker volume create "$vol" >/dev/null
docker run --rm -u 0 -v "$vol:/t" "$image" chown "$(id -u):$(id -g)" /t >/dev/null
exec docker run --rm \
  --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges \
  --network none \
  -e HOME=/tmp/home -e CARGO_TARGET_DIR=/target -e CARGO_TERM_COLOR=never \
  -v "$repo:/work" -v "$vol:/target" -w /work \
  "$image" sh -c "$*"
