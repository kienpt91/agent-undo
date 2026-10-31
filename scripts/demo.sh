#!/bin/sh
# Scripted demonstration: a fake project, a scripted "agent" that edits, deletes and
# writes files (including a fake env file), then log / diff / undo preview / undo / verify.
# Everything happens in temp directories. Run inside the container:
#   scripts/dev.sh 'cargo build --release && AU=/target/release/agent-undo scripts/demo.sh'
set -eu
AU=${AU:-agent-undo}
work=$(mktemp -d)
export XDG_STATE_HOME="$work/state"
export HOME="$work/home"
mkdir -p "$HOME" "$work/shop/src"
cd "$work/shop"

cat > src/main.rs <<'RS'
fn main() {
    println!("checkout v1");
}
RS
cat > src/pricing.rs <<'RS'
pub fn total(cents: &[u64]) -> u64 {
    cents.iter().sum()
}
RS
printf '# shop\nA tiny demo project.\n' > README.md
printf 'DB_PASSWORD=demo-only-not-a-real-secret\n' > .env

# The scripted "agent".
cat > agent.sh <<'SH'
printf 'fn main() {\n    println!("checkout v2 (agent was here)");\n}\n' > src/main.rs
rm src/pricing.rs
mkdir docs
printf '# Plan\n1. rewrite checkout\n' > docs/plan.md
chmod +x agent.sh
printf 'DB_PASSWORD=changed-by-the-agent\n' > .env
SH

echo '$ agent-undo init'
$AU init
echo
echo '$ agent-undo run --label "fake agent" -- sh agent.sh'
$AU run --label "fake agent" -- sh ./agent.sh
echo
echo '$ agent-undo log'
$AU log
echo
echo '$ agent-undo diff 2'
$AU diff 2
echo
echo '$ agent-undo undo 2        # dry run: nothing is changed'
$AU undo 2 || true
echo
echo '$ agent-undo undo 2 --apply'
$AU undo 2 --apply
echo
echo '$ agent-undo verify'
$AU verify
echo
echo '$ cat src/main.rs; ls src docs; cat .env'
cat src/main.rs
ls src
ls docs 2>&1 || true
cat .env
echo
echo '$ agent-undo log'
$AU log
echo
echo '$ agent-undo undo --last --apply     # undo the undo'
$AU undo --last --apply
echo
echo '$ agent-undo verify'
$AU verify
rm -rf "$work"
