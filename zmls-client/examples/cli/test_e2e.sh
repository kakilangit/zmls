#!/usr/bin/env bash
# End-to-end tests for the zmls-cli (zmls-client edition).
#
# Usage:
#   ./test_e2e.sh [path-to-zmls-cli]
#
# If no path given, defaults to ../../zig-out/bin/zmls-cli
# (relative to this script's directory).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLI="${1:-${SCRIPT_DIR}/../../zig-out/bin/zmls-cli}"

PASS=0
FAIL=0
SKIP=0
TMPDIR=""

cleanup() {
    if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
        rm -rf "$TMPDIR"
    fi
}
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); echo "  [v] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [x] $1: $2"; }

# Create temp workspace.
TMPDIR="$(mktemp -d)"
ALICE="$TMPDIR/alice"
BOB="$TMPDIR/bob"
CAROL="$TMPDIR/carol"
mkdir -p "$ALICE" "$BOB" "$CAROL"

echo "zmls-cli e2e tests"
echo "binary: $CLI"
echo ""

# ── Test 1: init ─────────────────────────────────────────

echo "test 1: init"
if (cd "$ALICE" && "$CLI" init test-group 2>/dev/null); then
    if [ -f "$ALICE/group.state" ] && [ -f "$ALICE/group.secrets" ]; then
        pass "init creates state and secrets files"
    else
        fail "init" "missing output files"
    fi
else
    fail "init" "command failed"
fi

# ── Test 2: info ─────────────────────────────────────────

echo "test 2: info"
INFO=$(cd "$ALICE" && "$CLI" info group.state 2>/dev/null)
if echo "$INFO" | grep -q "epoch=0"; then
    if echo "$INFO" | grep -q "leaves=1"; then
        pass "info shows epoch=0 leaves=1"
    else
        fail "info" "wrong leaf count"
    fi
else
    fail "info" "wrong epoch or command failed"
fi

# ── Test 3: key-package ──────────────────────────────────

echo "test 3: key-package"
if (cd "$BOB" && "$CLI" key-package bob 2>/dev/null); then
    if [ -f "$BOB/bob.kp" ] && [ -f "$BOB/bob.secret" ]; then
        pass "key-package creates kp and secret files"
    else
        fail "key-package" "missing output files"
    fi
else
    fail "key-package" "command failed"
fi

# ── Test 4: add ──────────────────────────────────────────

echo "test 4: add member"
cp "$BOB/bob.kp" "$ALICE/"
if (cd "$ALICE" && "$CLI" add group.state bob.kp 2>/dev/null); then
    if [ -f "$ALICE/welcome.bin" ] && \
       [ -f "$ALICE/commit.bin" ] && \
       [ -f "$ALICE/tree.bin" ] && \
       [ -f "$ALICE/signer.pub" ]; then
        pass "add creates welcome, commit, tree, signer"
    else
        fail "add" "missing output files"
    fi
else
    fail "add" "command failed"
fi

# Verify Alice advanced to epoch 1.
INFO=$(cd "$ALICE" && "$CLI" info group.state 2>/dev/null)
if echo "$INFO" | grep -q "epoch=1" && \
   echo "$INFO" | grep -q "leaves=2"; then
    pass "add advances epoch to 1 with 2 leaves"
else
    fail "add" "unexpected state: $INFO"
fi

# ── Test 5: join ─────────────────────────────────────────

echo "test 5: join via Welcome"
cp "$ALICE/welcome.bin" "$BOB/"
cp "$ALICE/tree.bin" "$BOB/"
cp "$ALICE/signer.pub" "$BOB/"
if (cd "$BOB" && "$CLI" join welcome.bin bob.secret bob.kp 2>/dev/null); then
    INFO=$(cd "$BOB" && "$CLI" info group.state 2>/dev/null)
    if echo "$INFO" | grep -q "epoch=1" && \
       echo "$INFO" | grep -q "leaves=2"; then
        pass "join succeeds, epoch=1 leaves=2"
    else
        fail "join" "unexpected state: $INFO"
    fi
else
    fail "join" "command failed"
fi

# ── Test 6: send + recv ──────────────────────────────────

echo "test 6: send + recv"
if (cd "$ALICE" && "$CLI" send group.state "hello from alice" 2>/dev/null); then
    cp "$ALICE/message.bin" "$BOB/"
    RECV=$(cd "$BOB" && "$CLI" recv group.state message.bin 2>/dev/null)
    if echo "$RECV" | grep -q "hello from alice"; then
        pass "send + recv round-trip"
    else
        fail "send+recv" "decrypted text mismatch: $RECV"
    fi
else
    fail "send" "command failed"
fi

# ── Test 7: export ───────────────────────────────────────

echo "test 7: export secret"
EXPORTED=$(cd "$ALICE" && "$CLI" export group.state test-export 32 2>/dev/null)
if [ ${#EXPORTED} -eq 64 ]; then
    pass "export returns 32-byte hex"
else
    fail "export" "unexpected length: ${#EXPORTED}"
fi

# ── Test 8: group-info ───────────────────────────────────

echo "test 8: group-info"
if (cd "$ALICE" && "$CLI" group-info group.state 2>/dev/null); then
    if [ -f "$ALICE/group-info.bin" ]; then
        pass "group-info creates group-info.bin"
    else
        fail "group-info" "missing output file"
    fi
else
    fail "group-info" "command failed"
fi

# ── Test 9: external-join ────────────────────────────────

echo "test 9: external-join"
cp "$ALICE/group-info.bin" "$CAROL/"
if (cd "$CAROL" && "$CLI" external-join group-info.bin carol 2>/dev/null); then
    if [ -f "$CAROL/group.state" ] && \
       [ -f "$CAROL/external-commit.bin" ]; then
        pass "external-join creates state and commit"
    else
        fail "external-join" "missing output files"
    fi
else
    fail "external-join" "command failed"
fi

# ── Test 10: key update + message exchange ───────────────
#
# Alice commits (key update), Bob processes, then they
# exchange messages using the new epoch keys.

echo "test 10: key update then message exchange"
if (cd "$ALICE" && "$CLI" commit group.state 2>/dev/null); then
    INFO=$(cd "$ALICE" && "$CLI" info group.state 2>/dev/null)
    if echo "$INFO" | grep -q "epoch=2"; then
        pass "commit advances epoch to 2"
    else
        fail "key-update" "unexpected epoch: $INFO"
    fi
else
    fail "key-update" "commit failed"
fi

# Bob processes the key-update commit.
cp "$ALICE/commit.bin" "$BOB/"
if (cd "$BOB" && "$CLI" process group.state commit.bin 2>/dev/null); then
    BOB_INFO=$(cd "$BOB" && "$CLI" info group.state 2>/dev/null)
    if echo "$BOB_INFO" | grep -q "epoch=2"; then
        pass "bob processed key-update, epoch=2"
    else
        fail "key-update" "bob wrong epoch: $BOB_INFO"
    fi
else
    fail "key-update" "bob process failed"
fi

# Alice sends with new keys, Bob decrypts.
if (cd "$ALICE" && "$CLI" send group.state "post-update-msg" 2>/dev/null); then
    cp "$ALICE/message.bin" "$BOB/"
    RECV=$(cd "$BOB" && "$CLI" recv group.state message.bin 2>/dev/null)
    if echo "$RECV" | grep -q "post-update-msg"; then
        pass "message after key update decrypts"
    else
        fail "key-update" "decrypt mismatch: $RECV"
    fi
else
    fail "key-update" "send after update failed"
fi

# ── Test 11: member removal + message isolation ──────────
#
# Fresh three-party group: Alice, Bob2, Carol2.
# Alice removes Bob2. Carol2 processes removal.
# Alice sends a message — Carol2 can decrypt but Bob2 cannot.

echo "test 11: member removal + message isolation"
ALICE2="$TMPDIR/alice2"
BOB2="$TMPDIR/bob2"
CAROL2="$TMPDIR/carol2"
mkdir -p "$ALICE2" "$BOB2" "$CAROL2"

# Alice2 creates group.
(cd "$ALICE2" && "$CLI" init removal-test 2>/dev/null)

# Bob2 + Carol2 generate key packages.
(cd "$BOB2" && "$CLI" key-package bob2 2>/dev/null)
(cd "$CAROL2" && "$CLI" key-package carol2 2>/dev/null)

# Alice2 adds Bob2.
cp "$BOB2/bob2.kp" "$ALICE2/"
(cd "$ALICE2" && "$CLI" add group.state bob2.kp 2>/dev/null)
cp "$ALICE2/welcome.bin" "$BOB2/"
cp "$ALICE2/tree.bin" "$BOB2/"
cp "$ALICE2/signer.pub" "$BOB2/"
(cd "$BOB2" && "$CLI" join welcome.bin bob2.secret bob2.kp 2>/dev/null)

# Alice2 adds Carol2.
cp "$CAROL2/carol2.kp" "$ALICE2/"
(cd "$ALICE2" && "$CLI" add group.state carol2.kp 2>/dev/null)

# Bob2 processes add-carol commit.
cp "$ALICE2/commit.bin" "$BOB2/"
(cd "$BOB2" && "$CLI" process group.state commit.bin 2>/dev/null)

# Carol2 joins via Welcome.
cp "$ALICE2/welcome.bin" "$CAROL2/"
cp "$ALICE2/tree.bin" "$CAROL2/"
cp "$ALICE2/signer.pub" "$CAROL2/"
(cd "$CAROL2" && "$CLI" join welcome.bin carol2.secret carol2.kp 2>/dev/null)

# Verify all three at epoch 2, 3 leaves.
A2_INFO=$(cd "$ALICE2" && "$CLI" info group.state 2>/dev/null)
B2_INFO=$(cd "$BOB2" && "$CLI" info group.state 2>/dev/null)
C2_INFO=$(cd "$CAROL2" && "$CLI" info group.state 2>/dev/null)
if echo "$A2_INFO" | grep -q "epoch=2" && \
   echo "$B2_INFO" | grep -q "epoch=2" && \
   echo "$C2_INFO" | grep -q "epoch=2"; then
    pass "three-party group at epoch=2"
else
    fail "removal" "epoch mismatch: A=$A2_INFO B=$B2_INFO C=$C2_INFO"
fi

# Alice2 removes Bob2 (leaf index 1).
if (cd "$ALICE2" && "$CLI" remove group.state 1 2>/dev/null); then
    pass "alice removed bob2"
else
    fail "removal" "remove command failed"
fi

# Carol2 processes the remove commit.
cp "$ALICE2/commit.bin" "$CAROL2/"
if (cd "$CAROL2" && "$CLI" process group.state commit.bin 2>/dev/null); then
    C2_INFO=$(cd "$CAROL2" && "$CLI" info group.state 2>/dev/null)
    if echo "$C2_INFO" | grep -q "epoch=3"; then
        pass "carol processed removal, epoch=3"
    else
        fail "removal" "carol wrong state: $C2_INFO"
    fi
else
    fail "removal" "carol process failed"
fi

# Alice2 sends message post-removal — Carol2 decrypts.
if (cd "$ALICE2" && "$CLI" send group.state "after-remove" 2>/dev/null); then
    cp "$ALICE2/message.bin" "$CAROL2/"
    RECV=$(cd "$CAROL2" && "$CLI" recv group.state message.bin 2>/dev/null)
    if echo "$RECV" | grep -q "after-remove"; then
        pass "carol decrypts post-removal message"
    else
        fail "removal" "decrypt mismatch: $RECV"
    fi
else
    fail "removal" "send after removal failed"
fi

# Bob2 should NOT be able to decrypt (stale epoch).
cp "$ALICE2/message.bin" "$BOB2/"
if (cd "$BOB2" && "$CLI" recv group.state message.bin 2>/dev/null); then
    fail "removal" "bob2 decrypted after removal (should fail)"
else
    pass "bob2 cannot decrypt after removal (expected)"
fi

# ── Summary ──────────────────────────────────────────────

echo ""
echo "results: $PASS passed, $FAIL failed, $SKIP skipped"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
