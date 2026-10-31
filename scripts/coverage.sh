#!/bin/sh
# Source-based coverage with rustc's own instrumentation and the llvm tools from
# the official `llvm-tools-preview` component (inside the container:
#   scripts/dev.sh scripts/coverage.sh).
# Unit tests live in `tests.rs` files and integration tests in `tests/`, both excluded
# from the numbers, as is `fakes.rs` (test support that lives in the application crate;
# it is reported on its own line).
set -eu
export CARGO_TARGET_DIR=/target/cov
export RUSTFLAGS="-C instrument-coverage"
rm -rf /tmp/cov && mkdir -p /tmp/cov
export LLVM_PROFILE_FILE=/tmp/cov/%p-%m.profraw
cargo test --workspace --no-fail-fast 2>&1 | grep -E '^(test result|error|failures)' || true
sysroot=$(rustc --print sysroot)
host=$(rustc -vV | sed -n 's/^host: //p')
bin="$sysroot/lib/rustlib/$host/bin"
"$bin/llvm-profdata" merge -sparse /tmp/cov/*.profraw -o /tmp/cov/all.profdata
objs=""
for f in "$CARGO_TARGET_DIR"/debug/deps/*; do
  case "$f" in *.*) continue ;; esac
  [ -f "$f" ] && [ -x "$f" ] && objs="$objs -object $f"
done
objs="$objs -object $CARGO_TARGET_DIR/debug/agent-undo"
ignore='(/tests/|/tests\.rs$|/\.cargo/|/rustc/|/registry/)'
report() { # name, then source paths
  name=$1; shift
  # shellcheck disable=SC2086
  "$bin/llvm-cov" report $objs -instr-profile=/tmp/cov/all.profdata \
    --ignore-filename-regex="$ignore" "$@" 2>/dev/null |
    awk -v name="$name" '/^TOTAL/ { printf "%-16s lines %6d  missed %5d  cover %s   functions %s\n", name, $8, $9, $10, $7 }'
}
w=$(pwd)
echo
echo "Line coverage (llvm-cov, test code excluded)"
report "domain" "$w/crates/domain/src"
report "application" "$w/crates/app/src/error.rs" "$w/crates/app/src/events.rs" "$w/crates/app/src/ports.rs" "$w/crates/app/src/usecases"
report "app fakes" "$w/crates/app/src/fakes.rs"
report "infrastructure" "$w/crates/infra/src"
report "cli" "$w/crates/cli/src"
echo
# overall = everything except fakes (test support)
# shellcheck disable=SC2086
"$bin/llvm-cov" report $objs -instr-profile=/tmp/cov/all.profdata \
  --ignore-filename-regex="$ignore|fakes\.rs" "$w/crates" 2>/dev/null |
  awk '/^TOTAL/ { printf "%-16s lines %6d  missed %5d  cover %s   functions %s\n", "overall", $8, $9, $10, $7 }'
echo
echo "Per-file line coverage below 90% (excluding fakes):"
# shellcheck disable=SC2086
"$bin/llvm-cov" report $objs -instr-profile=/tmp/cov/all.profdata \
  --ignore-filename-regex="$ignore|fakes\.rs" "$w/crates" 2>/dev/null |
  awk 'NR>2 && $1 ~ /crates/ { c=$10; sub("%","",c); if (c+0 < 90) printf "  %-60s %s (missed %s of %s lines)\n", $1, $10, $9, $8 }'
