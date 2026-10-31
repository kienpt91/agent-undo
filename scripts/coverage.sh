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
# shellcheck disable=SC2086
"$bin/llvm-cov" report $objs -instr-profile=/tmp/cov/all.profdata \
  --ignore-filename-regex="$ignore" 2>/dev/null > /tmp/cov/report.txt
echo
echo "Line coverage by layer (llvm-cov; unit and integration test code excluded)"
awk '
  NR > 2 && $1 ~ /\/src\// {
    split($1, parts, "/"); layer = parts[1]
    if ($1 ~ /fakes\.rs$/) layer = "app-fakes"
    lines[layer] += $8; missed[layer] += $9
    if (layer != "app-fakes") { tl += $8; tm += $9 }
    if ($8 > 0) { c = ($8 - $9) * 100 / $8; if (c < 90 && layer != "app-fakes") low[$1] = sprintf("%.1f%% (%d of %d lines missed)", c, $9, $8) }
  }
  END {
    order[1] = "domain"; order[2] = "app"; order[3] = "infra"; order[4] = "cli"; order[5] = "app-fakes"
    for (i = 1; i <= 5; i++) {
      l = order[i]
      if (lines[l] > 0) printf "%-12s %6d lines  %5d missed  %6.2f%%\n", l, lines[l], missed[l], (lines[l] - missed[l]) * 100 / lines[l]
    }
    printf "%-12s %6d lines  %5d missed  %6.2f%%   (all layers, fakes excluded)\n", "overall", tl, tm, (tl - tm) * 100 / tl
    print ""
    print "Files below 90% line coverage (fakes excluded):"
    n = 0
    for (f in low) { printf "  %-48s %s\n", f, low[f]; n++ }
    if (n == 0) print "  none"
  }' /tmp/cov/report.txt
