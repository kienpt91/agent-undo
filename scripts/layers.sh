#!/bin/sh
# Runs the test suites layer by layer (inside the container: scripts/dev.sh scripts/layers.sh).
set -eu
echo "== domain: pure unit and property-style tests =="
cargo test -p agent-undo-domain
echo "== application: use cases against in-memory fakes =="
cargo test -p agent-undo-app
echo "== infrastructure: contract tests (fake and filesystem adapter) and security/resource tests =="
cargo test -p agent-undo-infra
echo "== architecture rules =="
cargo test -p agent-undo --test architecture
echo "== command line: unit tests and end-to-end tests of the real binary =="
cargo test -p agent-undo --lib --bins
for t in $(ls crates/cli/tests/*.rs | xargs -n1 basename | sed 's/\.rs$//' | grep -v '^architecture$'); do
  cargo test -p agent-undo --test "$t"
done
