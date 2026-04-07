#!/bin/sh
# End-to-end CLI tests for zmls.
# Usage: ./test_e2e.sh [path-to-zmls-cli]
#
# Tests exercise the working subcommands: init, key-package,
# add, commit, remove, export, info.
# join/send/recv are stubs and are skipped.

set -e

CLI="${1:-../../zig-out/bin/zmls-cli}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo 0 > "$WORK/.pass"
echo 0 > "$WORK/.fail"
echo 0 > "$WORK/.skip"

ok() {
    n=$(cat "$WORK/.pass")
    echo $((n + 1)) > "$WORK/.pass"
    printf "  PASS: %s\n" "$1"
}
ko() {
    n=$(cat "$WORK/.fail")
    echo $((n + 1)) > "$WORK/.fail"
    printf "  FAIL: %s\n" "$1"
}
sk() {
    n=$(cat "$WORK/.skip")
    echo $((n + 1)) > "$WORK/.skip"
    printf "  SKIP: %s\n" "$1"
}

run() { "$CLI" "$@" >/dev/null 2>&1; }

# ── Test 1: Alice creates group, Bob key-package, Alice adds
echo "test 1: create group + add member"
D="$WORK/t1" && mkdir -p "$D" && cd "$D"
run init mygroup
run key-package bob
run add group.state bob.kp
"$CLI" info group.state 2>/dev/null > info.txt
grep -q "epoch: 1" info.txt && ok "epoch advanced to 1" || ko "epoch not 1"
grep -q "leaves: 2" info.txt && ok "two leaves" || ko "leaf count wrong"
[ -f welcome.bin ] && ok "welcome.bin created" || ko "no welcome.bin"

# ── Test 2: key update (empty commit with path)
echo "test 2: key update via empty commit"
D="$WORK/t2" && mkdir -p "$D" && cd "$D"
run init mygroup
run key-package bob
run add group.state bob.kp
run commit group.state
"$CLI" info group.state 2>/dev/null > info.txt
grep -q "epoch: 2" info.txt && ok "epoch advanced to 2" || ko "epoch not 2"

# ── Test 3: member removal (3-party, remove one)
echo "test 3: member removal"
D="$WORK/t3" && mkdir -p "$D" && cd "$D"
run init mygroup
run key-package bob
run add group.state bob.kp
run key-package carol
run add group.state carol.kp
run remove group.state 1
"$CLI" info group.state 2>/dev/null > info.txt
grep -q "epoch: 3" info.txt && ok "epoch advanced to 3" || ko "epoch not 3"
grep -q "leaves: 3" info.txt && ok "leaves still 3 (blank)" || ko "leaf count wrong"

# ── Test 4: MLS exporter
echo "test 4: MLS exporter"
D="$WORK/t4" && mkdir -p "$D" && cd "$D"
run init mygroup
out=$("$CLI" export group.state test-label 16 2>/dev/null)
len=$(printf '%s' "$out" | wc -c | tr -d ' ')
[ "$len" = "32" ] && ok "export 32 hex chars" || ko "export len=$len"
out2=$("$CLI" export group.state other-label 16 2>/dev/null)
[ "$out" != "$out2" ] && ok "different labels differ" || ko "same output"

# ── Test 5: three-party group
echo "test 5: three-party group"
D="$WORK/t5" && mkdir -p "$D" && cd "$D"
run init mygroup
run key-package bob
run add group.state bob.kp
run key-package carol
run add group.state carol.kp
"$CLI" info group.state 2>/dev/null > info.txt
grep -q "epoch: 2" info.txt && ok "epoch 2 after two adds" || ko "epoch wrong"
grep -q "leaves: 3" info.txt && ok "three leaves" || ko "leaf count wrong"

# ── Stubs
echo "test 6: join via Welcome"
sk "join not fully wired"
echo "test 7: send/recv"
sk "send/recv not wired"
echo "test 8: external join"
sk "external join not wired"

# ── Summary
pass=$(cat "$WORK/.pass")
fail=$(cat "$WORK/.fail")
skip=$(cat "$WORK/.skip")
echo ""
echo "results: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ] || exit 1
