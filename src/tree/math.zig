//! Pure array-based binary tree index arithmetic per RFC 9420
//! Appendix C. Provides parent/child/sibling navigation for
//! ratchet tree node indices.
//
// Array-based binary tree index arithmetic per RFC 9420 Appendix C.
//
// A ratchet tree with `n` leaves is stored in an array of
// `nodeWidth(n)` nodes. When `n` is not a power of 2, the tree
// is logically embedded in the smallest complete binary tree that
// contains `n` leaves. Surplus positions are blank.
//
// Note on nodeWidth: RFC Appendix C defines node_width(n) = 2n-1,
// but for non-power-of-2 n, the parent() formula produces node
// indices up to 2*ceil_pow2(n)-2 (exceeding 2n-2). This impl
// uses nodeWidth = 2*paddedLeafCount(n)-1 to ensure all reachable
// indices have valid array positions. The wire-visible outputs
// (root, directPath, copath, parent) are identical to the RFC
// pseudocode. RFC §4.1: "MLS places no requirements on
// implementations' internal representations."
//
// All functions are pure: no allocations, no state, no side effects.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");

const NodeIndex = types.NodeIndex;
const LeafIndex = types.LeafIndex;

/// The level of a node in the tree. Leaves are level 0.
/// For a parent, the level is 1 + the number of trailing
/// 1 bits in the index.
pub fn level(x: NodeIndex) u32 {
    const n = x.toU32();
    if (n & 0x01 == 0) return 0;
    var k: u32 = 0;
    // Loop bounded by u32 bit width (max 31 iterations).
    while (k < 32 and (n >> @intCast(k)) & 0x01 == 1) {
        k += 1;
    }
    return k;
}

/// The number of nodes needed to represent a tree with `n`
/// leaves. For non-power-of-2 `n`, the tree is embedded in
/// the smallest complete binary tree, so the width equals
/// `2 * paddedLeafCount(n) - 1`.
pub fn nodeWidth(n: u32) u32 {
    if (n == 0) return 0;
    return 2 * paddedLeafCount(n) - 1;
}

/// Round `n` up to the next power of 2. Returns `n` unchanged
/// when `n` is already a power of 2. Returns 1 for n <= 1.
/// Maximum leaf count. Trees above this cause shift overflow.
pub const max_leaves: u32 = 1 << 30;

pub fn paddedLeafCount(n: u32) u32 {
    if (n <= 1) return n;
    if (n > max_leaves) @panic("tree too large");
    // Bit trick: ceil power of 2.
    const v = n - 1;
    const shift: u5 = @intCast(
        @bitSizeOf(u32) - @clz(v),
    );
    return @as(u32, 1) << shift;
}

/// The index of the root node of a tree with `n` leaves.
/// For non-power-of-2 `n`, returns the root of the smallest
/// complete binary tree that contains `n` leaves.
pub fn root(n: u32) NodeIndex {
    if (n == 0) @panic("root: n must be > 0");
    const w = nodeWidth(n);
    return NodeIndex.fromU32(
        (@as(u32, 1) << @intCast(log2(w))) - 1,
    );
}

/// The left child of an intermediate node. Panics on leaf
/// nodes.
pub fn left(x: NodeIndex) NodeIndex {
    const k = level(x);
    if (k == 0) @panic("left: leaf has no children");
    return NodeIndex.fromU32(
        x.toU32() ^ (@as(u32, 1) << @intCast(k - 1)),
    );
}

/// The right child of an intermediate node. Panics on leaf
/// nodes.
pub fn right(x: NodeIndex) NodeIndex {
    const k = level(x);
    if (k == 0) @panic("right: leaf has no children");
    return NodeIndex.fromU32(
        x.toU32() ^ (@as(u32, 3) << @intCast(k - 1)),
    );
}

/// The parent of a node in a tree with `n` leaves. Panics on
/// the root.
pub fn parent(x: NodeIndex, n: u32) NodeIndex {
    assert(n > 0);
    if (x.toU32() == root(n).toU32())
        @panic("parent: root has no parent");
    const k = level(x);
    const b: u32 = (x.toU32() >> @intCast(k + 1)) & 0x01;
    return NodeIndex.fromU32(
        (x.toU32() | (@as(u32, 1) << @intCast(k))) ^
            (b << @intCast(k + 1)),
    );
}

/// The sibling of a node (the other child of its parent).
pub fn sibling(x: NodeIndex, n: u32) NodeIndex {
    assert(n > 0);
    const p = parent(x, n);
    if (x.toU32() < p.toU32()) {
        return right(p);
    } else {
        return left(p);
    }
}

/// Whether a node index corresponds to a leaf (even index).
pub fn isLeaf(x: NodeIndex) bool {
    return x.toU32() & 0x01 == 0;
}

/// Whether leaf_node is a descendant of ancestor_node.
/// A parent at level k covers node indices in
/// [p - (2^k - 1), p + (2^k - 1)].
pub fn isInSubtree(
    ancestor_node: NodeIndex,
    leaf: LeafIndex,
) bool {
    const p = ancestor_node.toU32();
    const l = leaf.toNodeIndex().toU32();
    const k = level(ancestor_node);
    if (k == 0) return p == l;
    const span = (@as(u32, 1) << @intCast(k)) - 1;
    return l >= p -| span and l <= p +| span;
}

/// The direct path of a node: the list of ancestors from the
/// node's parent up to and including the root. Returns an
/// empty slice for the root.
pub fn directPath(
    x: NodeIndex,
    n: u32,
    buf: *[32]NodeIndex,
) []NodeIndex {
    assert(n > 0);
    const r = root(n);
    if (x.toU32() == r.toU32()) return buf[0..0];

    var count: usize = 0;
    var current = x;
    while (current.toU32() != r.toU32()) {
        current = parent(current, n);
        buf[count] = current;
        count += 1;
    }
    return buf[0..count];
}

/// The copath of a node: the sibling of each node on the
/// direct path (excluding the root).
pub fn copath(
    x: NodeIndex,
    n: u32,
    buf: *[32]NodeIndex,
) []NodeIndex {
    assert(n > 0);
    const r = root(n);
    if (x.toU32() == r.toU32()) return buf[0..0];

    // Build chain: [x, parent(x), ...] excluding root.
    var chain: [33]NodeIndex = undefined;
    var chain_len: usize = 0;
    chain[0] = x;
    chain_len = 1;

    var current = x;
    while (current.toU32() != r.toU32()) {
        current = parent(current, n);
        if (current.toU32() != r.toU32()) {
            chain[chain_len] = current;
            chain_len += 1;
        }
    }

    for (chain[0..chain_len], 0..) |node, i| {
        buf[i] = sibling(node, n);
    }
    return buf[0..chain_len];
}

/// Shift right by a u6 amount, saturating at 0 for >= 32.
fn shr32(v: u32, amt: u6) u32 {
    if (amt >= 32) return 0;
    return v >> @as(u5, @intCast(amt));
}

/// The lowest common ancestor of two nodes.
pub fn commonAncestor(
    x: NodeIndex,
    y: NodeIndex,
) NodeIndex {
    const lx: u6 = @intCast(level(x) + 1);
    const ly: u6 = @intCast(level(y) + 1);

    if (lx <= ly and ly <= 32 and
        shr32(x.toU32(), ly) == shr32(y.toU32(), ly))
    {
        return y;
    }
    if (ly <= lx and lx <= 32 and
        shr32(x.toU32(), lx) == shr32(y.toU32(), lx))
    {
        return x;
    }

    var xn = x.toU32();
    var yn = y.toU32();
    var k: u6 = 0;
    while (xn != yn) {
        xn >>= 1;
        yn >>= 1;
        k += 1;
    }
    return NodeIndex.fromU32(
        (xn << @as(u5, @intCast(k))) +
            (@as(u32, 1) << @as(u5, @intCast(k - 1))) - 1,
    );
}

/// Floor of log2 for a positive integer. Returns 0 for 0.
fn log2(x: u32) u32 {
    if (x == 0) return 0;
    return @bitSizeOf(u32) - 1 - @clz(x);
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;

test "paddedLeafCount rounds up to power of 2" {
    try testing.expectEqual(@as(u32, 0), paddedLeafCount(0));
    try testing.expectEqual(@as(u32, 1), paddedLeafCount(1));
    try testing.expectEqual(@as(u32, 2), paddedLeafCount(2));
    try testing.expectEqual(@as(u32, 4), paddedLeafCount(3));
    try testing.expectEqual(@as(u32, 4), paddedLeafCount(4));
    try testing.expectEqual(@as(u32, 8), paddedLeafCount(5));
    try testing.expectEqual(@as(u32, 8), paddedLeafCount(6));
    try testing.expectEqual(@as(u32, 8), paddedLeafCount(7));
    try testing.expectEqual(@as(u32, 8), paddedLeafCount(8));
    try testing.expectEqual(@as(u32, 16), paddedLeafCount(9));
    try testing.expectEqual(@as(u32, 64), paddedLeafCount(33));
}

test "nodeWidth with non-power-of-2 leaf counts" {
    // Power-of-2 unchanged.
    try testing.expectEqual(@as(u32, 0), nodeWidth(0));
    try testing.expectEqual(@as(u32, 1), nodeWidth(1));
    try testing.expectEqual(@as(u32, 3), nodeWidth(2));
    try testing.expectEqual(@as(u32, 7), nodeWidth(4));
    try testing.expectEqual(@as(u32, 15), nodeWidth(8));

    // Non-power-of-2: padded to next complete tree.
    try testing.expectEqual(@as(u32, 7), nodeWidth(3));
    try testing.expectEqual(@as(u32, 15), nodeWidth(5));
    try testing.expectEqual(@as(u32, 15), nodeWidth(6));
    try testing.expectEqual(@as(u32, 15), nodeWidth(7));
    try testing.expectEqual(@as(u32, 31), nodeWidth(9));
    try testing.expectEqual(@as(u32, 31), nodeWidth(15));
}

test "level of nodes" {
    try testing.expectEqual(@as(u32, 0), level(NodeIndex.fromU32(0)));
    try testing.expectEqual(@as(u32, 0), level(NodeIndex.fromU32(2)));
    try testing.expectEqual(@as(u32, 0), level(NodeIndex.fromU32(4)));
    try testing.expectEqual(@as(u32, 1), level(NodeIndex.fromU32(1)));
    try testing.expectEqual(@as(u32, 2), level(NodeIndex.fromU32(3)));
    try testing.expectEqual(@as(u32, 3), level(NodeIndex.fromU32(7)));
}

test "root index" {
    try testing.expectEqual(@as(u32, 0), root(1).toU32());
    try testing.expectEqual(@as(u32, 1), root(2).toU32());
    try testing.expectEqual(@as(u32, 3), root(4).toU32());
    try testing.expectEqual(@as(u32, 7), root(8).toU32());
    // Non-power-of-2: root of padded tree.
    try testing.expectEqual(@as(u32, 3), root(3).toU32());
    try testing.expectEqual(@as(u32, 7), root(5).toU32());
    try testing.expectEqual(@as(u32, 7), root(6).toU32());
    try testing.expectEqual(@as(u32, 7), root(7).toU32());
    try testing.expectEqual(@as(u32, 15), root(9).toU32());
}

test "left and right children" {
    try testing.expectEqual(
        @as(u32, 0),
        left(NodeIndex.fromU32(1)).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 2),
        right(NodeIndex.fromU32(1)).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 1),
        left(NodeIndex.fromU32(3)).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 5),
        right(NodeIndex.fromU32(3)).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 3),
        left(NodeIndex.fromU32(7)).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 11),
        right(NodeIndex.fromU32(7)).toU32(),
    );
}

test "parent node" {
    // 4-leaf tree.
    try testing.expectEqual(
        @as(u32, 1),
        parent(NodeIndex.fromU32(0), 4).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 1),
        parent(NodeIndex.fromU32(2), 4).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 5),
        parent(NodeIndex.fromU32(4), 4).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 3),
        parent(NodeIndex.fromU32(1), 4).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 3),
        parent(NodeIndex.fromU32(5), 4).toU32(),
    );
}

test "parent for non-power-of-2 leaf counts" {
    // 3 leaves: padded to 4-leaf tree (root=3, width=7).
    // Leaf 2 (node 4): parent = 5, which is valid in padded tree.
    try testing.expectEqual(
        @as(u32, 5),
        parent(NodeIndex.fromU32(4), 3).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 1),
        parent(NodeIndex.fromU32(0), 3).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 3),
        parent(NodeIndex.fromU32(5), 3).toU32(),
    );

    // 5 leaves: padded to 8-leaf tree (root=7, width=15).
    try testing.expectEqual(
        @as(u32, 9),
        parent(NodeIndex.fromU32(8), 5).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 11),
        parent(NodeIndex.fromU32(9), 5).toU32(),
    );
}

test "sibling for non-power-of-2 leaf counts" {
    // 3 leaves: padded to 4-leaf tree.
    // sibling(4, 3) = sibling of leaf 2 = left(parent(4,3))
    //   parent(4,3)=5, left(5)=4... no, left(5): level(5)=1,
    //   left = 5 ^ (1 << 0) = 4. So sibling(4,3) = 6.
    try testing.expectEqual(
        @as(u32, 6),
        sibling(NodeIndex.fromU32(4), 3).toU32(),
    );
    // sibling(0, 3) = 2.
    try testing.expectEqual(
        @as(u32, 2),
        sibling(NodeIndex.fromU32(0), 3).toU32(),
    );
    // sibling(1, 3) = 5.
    try testing.expectEqual(
        @as(u32, 5),
        sibling(NodeIndex.fromU32(1), 3).toU32(),
    );
}

test "sibling" {
    try testing.expectEqual(
        @as(u32, 2),
        sibling(NodeIndex.fromU32(0), 4).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 0),
        sibling(NodeIndex.fromU32(2), 4).toU32(),
    );
    try testing.expectEqual(
        @as(u32, 5),
        sibling(NodeIndex.fromU32(1), 4).toU32(),
    );
}

test "direct path" {
    var buf: [32]NodeIndex = undefined;
    const dp = directPath(NodeIndex.fromU32(0), 8, &buf);
    try testing.expectEqual(@as(usize, 3), dp.len);
    try testing.expectEqual(@as(u32, 1), dp[0].toU32());
    try testing.expectEqual(@as(u32, 3), dp[1].toU32());
    try testing.expectEqual(@as(u32, 7), dp[2].toU32());
}

test "direct path for 3-leaf tree" {
    var buf: [32]NodeIndex = undefined;
    // Leaf 0 (node 0) in 3-leaf tree (padded to 4, root=3).
    // Path: [1, 3].
    const dp0 = directPath(NodeIndex.fromU32(0), 3, &buf);
    try testing.expectEqual(@as(usize, 2), dp0.len);
    try testing.expectEqual(@as(u32, 1), dp0[0].toU32());
    try testing.expectEqual(@as(u32, 3), dp0[1].toU32());

    // Leaf 2 (node 4): path = [5, 3].
    const dp2 = directPath(NodeIndex.fromU32(4), 3, &buf);
    try testing.expectEqual(@as(usize, 2), dp2.len);
    try testing.expectEqual(@as(u32, 5), dp2[0].toU32());
    try testing.expectEqual(@as(u32, 3), dp2[1].toU32());
}

test "direct path for 5-leaf tree" {
    var buf: [32]NodeIndex = undefined;
    // 5 leaves, padded to 8 (root=7).
    // Leaf 4 (node 8): path = [9, 11, 7].
    const dp = directPath(NodeIndex.fromU32(8), 5, &buf);
    try testing.expectEqual(@as(usize, 3), dp.len);
    try testing.expectEqual(@as(u32, 9), dp[0].toU32());
    try testing.expectEqual(@as(u32, 11), dp[1].toU32());
    try testing.expectEqual(@as(u32, 7), dp[2].toU32());
}

test "direct path of root is empty" {
    var buf: [32]NodeIndex = undefined;
    const dp = directPath(root(8), 8, &buf);
    try testing.expectEqual(@as(usize, 0), dp.len);
}

test "copath" {
    var buf: [32]NodeIndex = undefined;
    const cp = copath(NodeIndex.fromU32(0), 8, &buf);
    try testing.expectEqual(@as(usize, 3), cp.len);
    try testing.expectEqual(@as(u32, 2), cp[0].toU32());
    try testing.expectEqual(@as(u32, 5), cp[1].toU32());
    try testing.expectEqual(@as(u32, 11), cp[2].toU32());
}

test "copath for 3-leaf tree" {
    var buf: [32]NodeIndex = undefined;
    // Leaf 0 in 3-leaf tree: copath = [2, 5].
    const cp = copath(NodeIndex.fromU32(0), 3, &buf);
    try testing.expectEqual(@as(usize, 2), cp.len);
    try testing.expectEqual(@as(u32, 2), cp[0].toU32());
    try testing.expectEqual(@as(u32, 5), cp[1].toU32());
}

test "common ancestor" {
    const ca = commonAncestor(
        NodeIndex.fromU32(0),
        NodeIndex.fromU32(8),
    );
    try testing.expectEqual(@as(u32, 7), ca.toU32());

    const ca2 = commonAncestor(
        NodeIndex.fromU32(0),
        NodeIndex.fromU32(4),
    );
    try testing.expectEqual(@as(u32, 3), ca2.toU32());

    const ca3 = commonAncestor(
        NodeIndex.fromU32(0),
        NodeIndex.fromU32(2),
    );
    try testing.expectEqual(@as(u32, 1), ca3.toU32());
}

test "isLeaf" {
    try testing.expect(isLeaf(NodeIndex.fromU32(0)));
    try testing.expect(isLeaf(NodeIndex.fromU32(2)));
    try testing.expect(isLeaf(NodeIndex.fromU32(4)));
    try testing.expect(!isLeaf(NodeIndex.fromU32(1)));
    try testing.expect(!isLeaf(NodeIndex.fromU32(3)));
    try testing.expect(!isLeaf(NodeIndex.fromU32(7)));
}

test "RFC Table 2: direct paths for 5-member tree" {
    // 5 members stored in an 8-leaf tree.
    var buf: [32]NodeIndex = undefined;
    const dp_a = directPath(NodeIndex.fromU32(0), 8, &buf);
    try testing.expectEqual(@as(usize, 3), dp_a.len);
    try testing.expectEqual(@as(u32, 1), dp_a[0].toU32());
    try testing.expectEqual(@as(u32, 3), dp_a[1].toU32());
    try testing.expectEqual(@as(u32, 7), dp_a[2].toU32());

    var buf2: [32]NodeIndex = undefined;
    const dp_e = directPath(NodeIndex.fromU32(8), 8, &buf2);
    try testing.expectEqual(@as(usize, 3), dp_e.len);
    try testing.expectEqual(@as(u32, 9), dp_e[0].toU32());
    try testing.expectEqual(@as(u32, 11), dp_e[1].toU32());
    try testing.expectEqual(@as(u32, 7), dp_e[2].toU32());
}

test "log2 correctness" {
    try testing.expectEqual(@as(u32, 0), log2(1));
    try testing.expectEqual(@as(u32, 1), log2(2));
    try testing.expectEqual(@as(u32, 1), log2(3));
    try testing.expectEqual(@as(u32, 2), log2(4));
    try testing.expectEqual(@as(u32, 2), log2(7));
    try testing.expectEqual(@as(u32, 3), log2(8));
    try testing.expectEqual(@as(u32, 3), log2(15));
    try testing.expectEqual(@as(u32, 4), log2(16));
}
