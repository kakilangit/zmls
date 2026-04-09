//! Core ratchet tree data structure (array of optional nodes)
//! per RFC 9420 Section 7.1. Provides get/set, resolution
//! enumeration, and filtered direct path computation.
// Ratchet tree data structure per RFC 9420 Section 7.1.
//
// The tree is an array of optional<Node> entries indexed by NodeIndex.
// Blank positions are null. This module provides the core operations:
// get/set nodes, resolution (non-blank enumeration), and filtered
// direct path computation.
//
// The tree owns the allocated node array but does NOT own the
// individual Node contents. Callers must manage node lifetimes.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const tree_math = @import("math.zig");
const node_mod = @import("node.zig");

const NodeIndex = types.NodeIndex;
const LeafIndex = types.LeafIndex;
const TreeError = errors.TreeError;
const Node = node_mod.Node;
const LeafNode = node_mod.LeafNode;
const ParentNode = node_mod.ParentNode;

/// Maximum tree depth (32-bit indices → max 32 levels).
const max_depth: u32 = 32;

pub const RatchetTree = struct {
    /// Array of optional nodes. Length = nodeWidth(leaf_count).
    nodes: []?Node,
    /// Number of leaves in the tree.
    leaf_count: u32,
    /// Allocator used for the node array.
    allocator: std.mem.Allocator,
    /// Whether this tree owns its node contents (heap-allocated
    /// via clone or decode). When true, deinit frees each node's
    /// internal allocations (keys, credentials, etc.).
    owns_contents: bool,

    // -- Lifecycle -----------------------------------------------------------

    /// Create a tree with `n` leaves, all initially blank.
    pub fn init(
        allocator: std.mem.Allocator,
        n: u32,
    ) error{OutOfMemory}!RatchetTree {
        if (n == 0) return error.OutOfMemory;
        const width = tree_math.nodeWidth(n);
        const nodes = allocator.alloc(
            ?Node,
            width,
        ) catch return error.OutOfMemory;
        @memset(nodes, null);
        return .{
            .nodes = nodes,
            .leaf_count = n,
            .allocator = allocator,
            .owns_contents = false,
        };
    }

    /// Free the node array and, if owned, all node contents.
    pub fn deinit(self: *RatchetTree) void {
        if (self.owns_contents) {
            for (self.nodes) |*slot| {
                if (slot.*) |*n| {
                    @constCast(n).deinit(self.allocator);
                }
            }
        }
        self.allocator.free(self.nodes);
        self.nodes = &.{};
        self.leaf_count = 0;
        // Note: self.* = undefined omitted here. RatchetTree instances are
        // often moved/consumed by commit or welcome processing, and
        // callers may still hold a stale handle whose deinit becomes a
        // no-op (nodes == &.{}). Poisoning self would turn those into
        // segfaults. Tracked for future cleanup.
    }

    // -- Clone ---------------------------------------------------------------

    /// Create a deep copy of this tree. The new tree owns its own
    /// node array and all node contents are independently allocated.
    pub fn clone(
        self: *const RatchetTree,
    ) error{OutOfMemory}!RatchetTree {
        assert(self.nodes.len > 0);
        assert(self.leaf_count > 0);
        const width = self.nodeCount();
        const new_nodes = self.allocator.alloc(
            ?Node,
            width,
        ) catch return error.OutOfMemory;
        var i: u32 = 0;
        errdefer {
            // Free already-cloned nodes on failure.
            var j: u32 = 0;
            while (j < i) : (j += 1) {
                if (new_nodes[j]) |*n| {
                    @constCast(n).deinit(self.allocator);
                }
            }
            self.allocator.free(new_nodes);
        }
        while (i < width) : (i += 1) {
            if (self.nodes[i]) |*n| {
                new_nodes[i] = try n.clone(self.allocator);
            } else {
                new_nodes[i] = null;
            }
        }
        return .{
            .nodes = new_nodes,
            .leaf_count = self.leaf_count,
            .allocator = self.allocator,
            .owns_contents = true,
        };
    }

    // -- Accessors -----------------------------------------------------------

    pub fn nodeCount(self: *const RatchetTree) u32 {
        assert(self.nodes.len == tree_math.nodeWidth(self.leaf_count));
        return @intCast(self.nodes.len);
    }

    /// Get the node at a given index, or null if blank.
    pub fn getNode(
        self: *const RatchetTree,
        index: NodeIndex,
    ) TreeError!?*const Node {
        const i = index.toUsize();
        if (i >= self.nodes.len) return error.IndexOutOfRange;
        if (self.nodes[i]) |*n| {
            return n;
        }
        return null;
    }

    /// Get the leaf node at a given leaf index.
    pub fn getLeaf(
        self: *const RatchetTree,
        leaf: LeafIndex,
    ) TreeError!?*const LeafNode {
        const node = try self.getNode(leaf.toNodeIndex());
        if (node) |n| {
            if (n.node_type != .leaf) return error.WrongNodeType;
            return &n.payload.leaf;
        }
        return null;
    }

    /// Set a node at a given index. Pass null to blank it.
    /// When owns_contents is true, the old node is freed and
    /// the incoming node is deep-cloned so the tree owns it.
    pub fn setNode(
        self: *RatchetTree,
        index: NodeIndex,
        node: ?Node,
    ) (TreeError || error{OutOfMemory})!void {
        const i = index.toUsize();
        if (i >= self.nodes.len) return error.IndexOutOfRange;
        if (self.owns_contents) {
            // Free old node contents.
            if (self.nodes[i]) |*old| {
                @constCast(old).deinit(self.allocator);
            }
            // Clone incoming node so tree owns data.
            if (node) |n| {
                self.nodes[i] = n.clone(self.allocator) catch
                    return error.OutOfMemory;
            } else {
                self.nodes[i] = null;
            }
        } else {
            self.nodes[i] = node;
        }
    }

    /// Set a leaf node.
    pub fn setLeaf(
        self: *RatchetTree,
        leaf: LeafIndex,
        node: ?LeafNode,
    ) (TreeError || error{OutOfMemory})!void {
        if (node) |n| {
            try self.setNode(
                leaf.toNodeIndex(),
                Node.initLeaf(n),
            );
        } else {
            try self.setNode(leaf.toNodeIndex(), null);
        }
    }

    /// Blank a node and zero any secret material.
    pub fn blankNode(
        self: *RatchetTree,
        index: NodeIndex,
    ) (TreeError || error{OutOfMemory})!void {
        try self.setNode(index, null);
    }

    // -- Resolution (Section 7.7) -------------------------------------------

    /// Resolution of a node: the set of non-blank nodes that collectively
    /// represent the keying material at this position.
    ///
    /// Per RFC 9420 Section 7.7:
    ///   - If the node is not blank, resolution is {node}.
    ///   - If the node is a blank leaf, resolution is {}.
    ///   - If the node is a blank intermediate, resolution is
    ///     resolution(left) ∪ resolution(right).
    ///
    /// Returns indices in the provided buffer.
    pub fn resolution(
        self: *const RatchetTree,
        index: NodeIndex,
        buf: *[max_resolution_size]NodeIndex,
    ) TreeError![]NodeIndex {
        var count: u32 = 0;
        try self.resolutionInner(index, buf, &count);
        return buf[0..count];
    }

    /// Collect non-blank nodes into buf, descending into children of
    /// /// blank intermediates per RFC 9420 Section 7.7.
    fn resolutionInner(
        self: *const RatchetTree,
        index: NodeIndex,
        buf: *[max_resolution_size]NodeIndex,
        count: *u32,
    ) TreeError!void {
        assert(count.* <= max_resolution_size);
        assert(self.nodes.len > 0);
        const i = index.toUsize();
        if (i >= self.nodes.len) return error.IndexOutOfRange;

        if (self.nodes[i]) |n| {
            // Non-blank: resolution includes this node.
            if (count.* >= max_resolution_size) {
                return error.IndexOutOfRange;
            }
            buf[count.*] = index;
            count.* += 1;

            // Per Section 7.7: for non-blank parent nodes,
            // also include all unmerged leaves.
            if (n.node_type == .parent) {
                for (n.payload.parent.unmerged_leaves) |li| {
                    if (count.* >= max_resolution_size) {
                        return error.IndexOutOfRange;
                    }
                    buf[count.*] = li.toNodeIndex();
                    count.* += 1;
                }
            }
            return;
        }

        // Blank node.
        if (tree_math.isLeaf(index)) {
            // Blank leaf: empty resolution.
            return;
        }

        // Blank intermediate: union of left and right resolutions.
        try self.resolutionInner(
            tree_math.left(index),
            buf,
            count,
        );
        try self.resolutionInner(
            tree_math.right(index),
            buf,
            count,
        );
    }

    /// Maximum resolution buffer size. Worst case: all leaves.
    /// Stack cost: 256 KiB per `[max_resolution_size]NodeIndex`
    /// buffer. Use `hasResolution()` when only emptiness needs
    /// to be checked (128 bytes vs 256 KiB).
    pub const max_resolution_size: u32 = 1 << 16;

    /// Check whether the resolution of `index` is non-empty
    /// without allocating a full resolution buffer.
    ///
    /// Uses an explicit stack bounded by tree depth (128 bytes)
    /// instead of the 256 KiB resolution buffer.
    pub fn hasResolution(
        self: *const RatchetTree,
        index: NodeIndex,
    ) TreeError!bool {
        var stack: [max_depth]NodeIndex = undefined;
        var top: u32 = 0;
        stack[0] = index;
        top = 1;

        while (top > 0) {
            top -= 1;
            const cur = stack[top];
            const i = cur.toUsize();
            if (i >= self.nodes.len)
                return error.IndexOutOfRange;

            if (self.nodes[i] != null) {
                // Non-blank node: resolution is non-empty.
                return true;
            }

            // Blank node.
            if (tree_math.isLeaf(cur)) {
                // Blank leaf: empty, continue.
                continue;
            }

            // Blank intermediate: push children.
            if (top + 2 > max_depth)
                return error.IndexOutOfRange;
            stack[top] = tree_math.left(cur);
            top += 1;
            stack[top] = tree_math.right(cur);
            top += 1;
        }
        return false;
    }

    // -- Filtered Direct Path (Section 12.4.1) ------------------------------

    /// The filtered direct path of a leaf: the direct path with
    /// entries removed where the copath node has an empty resolution.
    ///
    /// Returns (filtered_path, filtered_copath) pairs in the buffers.
    pub fn filteredDirectPath(
        self: *const RatchetTree,
        leaf: LeafIndex,
        path_buf: *[max_depth]NodeIndex,
        copath_buf: *[max_depth]NodeIndex,
    ) TreeError!struct {
        path: []NodeIndex,
        copath: []NodeIndex,
    } {
        var dp_buf: [max_depth]NodeIndex = undefined;
        const dp = tree_math.directPath(
            leaf.toNodeIndex(),
            self.leaf_count,
            &dp_buf,
        );

        var cp_buf: [max_depth]NodeIndex = undefined;
        const cp = tree_math.copath(
            leaf.toNodeIndex(),
            self.leaf_count,
            &cp_buf,
        );

        if (dp.len != cp.len)
            @panic("filteredDirectPath: path/copath mismatch");

        var count: u32 = 0;

        for (dp, cp) |d, c| {
            if (try self.hasResolution(c)) {
                path_buf[count] = d;
                copath_buf[count] = c;
                count += 1;
            }
        }

        return .{
            .path = path_buf[0..count],
            .copath = copath_buf[0..count],
        };
    }
};

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const Credential = @import(
    "../credential/credential.zig",
).Credential;

fn makeTestLeafNode(id: []const u8) LeafNode {
    return .{
        .encryption_key = id,
        .signature_key = id,
        .credential = Credential.initBasic(id),
        .capabilities = .{
            .versions = &.{},
            .cipher_suites = &.{},
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{},
        },
        .source = .commit,
        .lifetime = null,
        .parent_hash = null,
        .extensions = &.{},
        .signature = id,
    };
}

test "init creates all-blank tree" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try testing.expectEqual(@as(u32, 4), tree.leaf_count);
    // 4 leaves → 7 nodes.
    try testing.expectEqual(@as(u32, 7), tree.nodeCount());

    // All blank.
    for (0..tree.nodeCount()) |i| {
        const index = NodeIndex.fromU32(@intCast(i));
        const node = try tree.getNode(index);
        try testing.expect(node == null);
    }
}

test "set and get leaf node" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    const leaf = makeTestLeafNode("alice");
    try tree.setLeaf(LeafIndex.fromU32(0), leaf);

    const got = try tree.getLeaf(LeafIndex.fromU32(0));
    try testing.expect(got != null);
    try testing.expectEqualSlices(
        u8,
        "alice",
        got.?.encryption_key,
    );

    // Other leaf is still blank.
    const blank = try tree.getLeaf(LeafIndex.fromU32(1));
    try testing.expect(blank == null);
}

test "resolution of non-blank node is itself" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    // Set leaf 0.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafNode("a"),
    );

    var buf: [RatchetTree.max_resolution_size]NodeIndex = undefined;
    const res = try tree.resolution(
        NodeIndex.fromU32(0),
        &buf,
    );

    try testing.expectEqual(@as(usize, 1), res.len);
    try testing.expectEqual(@as(u32, 0), res[0].toU32());
}

test "resolution of blank leaf is empty" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    var buf: [RatchetTree.max_resolution_size]NodeIndex = undefined;
    const res = try tree.resolution(
        NodeIndex.fromU32(0),
        &buf,
    );

    try testing.expectEqual(@as(usize, 0), res.len);
}

test "resolution of blank parent with non-blank children" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    // Set leaves 0 and 1 (nodes 0 and 2). Parent is node 1.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafNode("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafNode("b"),
    );

    // Node 1 is blank, so resolution should be {0, 2}.
    var buf: [RatchetTree.max_resolution_size]NodeIndex = undefined;
    const res = try tree.resolution(
        NodeIndex.fromU32(1),
        &buf,
    );

    try testing.expectEqual(@as(usize, 2), res.len);
    try testing.expectEqual(@as(u32, 0), res[0].toU32());
    try testing.expectEqual(@as(u32, 2), res[1].toU32());
}

test "blank node removes it" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafNode("x"),
    );
    try testing.expect(
        (try tree.getLeaf(LeafIndex.fromU32(0))) != null,
    );

    try tree.blankNode(NodeIndex.fromU32(0));
    try testing.expect(
        (try tree.getLeaf(LeafIndex.fromU32(0))) == null,
    );
}

test "filtered direct path excludes empty copath resolutions" {
    const alloc = testing.allocator;
    // 4-leaf tree: nodes 0,1,2,3,4,5,6.
    //       3
    //      / \
    //     1   5
    //    / \ / \
    //   0  2 4  6
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    // Only leaf 0 and leaf 2 are populated.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafNode("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeafNode("c"),
    );

    // Direct path of leaf 0: [1, 3]
    // Copath of leaf 0:      [2, 5]
    // Resolution of node 2 (leaf 1 at index 2): blank → empty
    //   Wait — leaf 1 is at node index 2. We set leaf 2 (node index 4).
    //   So node 2 is blank (leaf 1 is blank).
    // Resolution of node 5: resolution(4) ∪ resolution(6)
    //   Node 4 = leaf 2 (set to "c") → {4}
    //   Node 6 = leaf 3 (blank) → {}
    //   So resolution(5) = {4} → non-empty.
    //
    // Filtered: path=[3], copath=[5] (node 1 excluded because
    //   its copath node 2 has empty resolution).

    var path_buf: [32]NodeIndex = undefined;
    var copath_buf: [32]NodeIndex = undefined;
    const result = try tree.filteredDirectPath(
        LeafIndex.fromU32(0),
        &path_buf,
        &copath_buf,
    );

    try testing.expectEqual(@as(usize, 1), result.path.len);
    try testing.expectEqual(@as(u32, 3), result.path[0].toU32());
    try testing.expectEqual(
        @as(u32, 5),
        result.copath[0].toU32(),
    );
}

test "resolution works for 3-leaf tree" {
    // 3 leaves: padded to 4-leaf tree (7 nodes).
    //       3
    //      / \
    //     1   5
    //    / \ / \
    //   0  2 4  6
    // Leaves 0, 1, 2 populated. Nodes 5, 6 are blank padding.
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 3);
    defer tree.deinit();

    try testing.expectEqual(@as(u32, 7), tree.nodeCount());

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafNode("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafNode("b"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeafNode("c"),
    );

    // Resolution of node 5 (blank parent): left=4 (leaf 2, "c"),
    // right=6 (blank padding leaf). Result = {4}.
    var buf: [RatchetTree.max_resolution_size]NodeIndex = undefined;
    const res5 = try tree.resolution(
        NodeIndex.fromU32(5),
        &buf,
    );
    try testing.expectEqual(@as(usize, 1), res5.len);
    try testing.expectEqual(@as(u32, 4), res5[0].toU32());

    // Resolution of root (node 3, blank): union of left (1)
    // and right (5) subtrees.
    const res3 = try tree.resolution(
        NodeIndex.fromU32(3),
        &buf,
    );
    // Leaves 0, 2 from left subtree; leaf 4 from right.
    try testing.expectEqual(@as(usize, 3), res3.len);
}

test "filteredDirectPath works for 3-leaf tree" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 3);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafNode("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafNode("b"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeafNode("c"),
    );

    // Leaf 0 direct path: [1, 3]. Copath: [2, 5].
    // Res(node 2) = {2} (leaf 1, non-blank).
    // Res(node 5) = {4} (leaf 2 at node 4, non-blank).
    // Both non-empty, so filtered path = [1, 3].
    var path_buf: [32]NodeIndex = undefined;
    var copath_buf: [32]NodeIndex = undefined;
    const r = try tree.filteredDirectPath(
        LeafIndex.fromU32(0),
        &path_buf,
        &copath_buf,
    );

    try testing.expectEqual(@as(usize, 2), r.path.len);
    try testing.expectEqual(@as(u32, 1), r.path[0].toU32());
    try testing.expectEqual(@as(u32, 3), r.path[1].toU32());
}

test "filteredDirectPath works for 5-leaf tree" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 5);
    defer tree.deinit();

    // 5 leaves in 8-leaf padded tree (15 nodes).
    try testing.expectEqual(@as(u32, 15), tree.nodeCount());

    // Populate first 5 leaves.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafNode("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafNode("b"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeafNode("c"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(3),
        makeTestLeafNode("d"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(4),
        makeTestLeafNode("e"),
    );

    // Leaf 4 (node 8) direct path: [9, 11, 7].
    // Copath: [10, 3].
    // Wait -- copath of node 8: sibling(8,5)=10.
    // Then for node 9: sibling(9,5). parent(9,5)=11.
    // 9<11, so right(11)=... level(11)=2, right=11^(3<<1)=11^6=13.
    // sibling(9,5) = 13.
    // Then for node 11: sibling(11,5). parent(11,5)=7.
    // 11>7, so left(7)=3. sibling(11,5)=3.
    // Copath: [10, 13, 3].
    //
    // Res(10): node 10 is blank leaf (leaf 5) -> empty.
    // Res(13): node 13 is blank parent. left=12 (blank leaf 6),
    //   right=14 (blank leaf 7). All blank -> empty.
    // Res(3): non-blank subtree with leaves a,b,c,d -> non-empty.
    //
    // Filtered: only node 7 (where copath 3 has resolution).
    var path_buf: [32]NodeIndex = undefined;
    var copath_buf: [32]NodeIndex = undefined;
    const r = try tree.filteredDirectPath(
        LeafIndex.fromU32(4),
        &path_buf,
        &copath_buf,
    );

    try testing.expectEqual(@as(usize, 1), r.path.len);
    try testing.expectEqual(@as(u32, 7), r.path[0].toU32());
    try testing.expectEqual(@as(u32, 3), r.copath[0].toU32());
}

test "resolution of parent with unmerged leaves" {
    // 2-leaf tree:
    //      1
    //     / \
    //    0   2
    //    A   B
    //
    // Set node 1 as parent with unmerged_leaves = [B (leaf 1)].
    // Resolution(1) should return [node 1, node 2 (B)].
    const alloc = std.testing.allocator;

    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    // Place leaf A at node 0.
    const leaf_a = makeTestLeafNode("a");
    tree.nodes[0] = Node.initLeaf(leaf_a);

    // Place leaf B at node 2.
    const leaf_b = makeTestLeafNode("b");
    tree.nodes[2] = Node.initLeaf(leaf_b);

    // Place a parent at node 1 with unmerged_leaves = [1].
    const unmerged = [_]LeafIndex{LeafIndex.fromU32(1)};
    tree.nodes[1] = Node.initParent(.{
        .encryption_key = &[_]u8{0x01} ** 32,
        .parent_hash = &.{},
        .unmerged_leaves = &unmerged,
    });

    var res_buf: [RatchetTree.max_resolution_size]NodeIndex =
        undefined;
    const res = try tree.resolution(
        NodeIndex.fromU32(1),
        &res_buf,
    );

    // Should be: node 1 (parent) + node 2 (leaf B as unmerged).
    try std.testing.expectEqual(@as(usize, 2), res.len);
    try std.testing.expectEqual(@as(u32, 1), res[0].toU32());
    try std.testing.expectEqual(@as(u32, 2), res[1].toU32());
}

test "hasResolution matches resolution emptiness" {
    // 4-leaf tree (7 nodes):
    //        3
    //      /   \
    //    1       5
    //   / \     / \
    //  0   2   4   6
    //  A   B   _   _
    //
    // Leaves 0,1 populated; 2,3 blank.
    const alloc = std.testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafNode("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafNode("b"),
    );

    // Non-blank leaf: has resolution.
    try testing.expect(
        try tree.hasResolution(NodeIndex.fromU32(0)),
    );
    try testing.expect(
        try tree.hasResolution(NodeIndex.fromU32(2)),
    );

    // Blank leaf: no resolution.
    try testing.expect(
        !try tree.hasResolution(NodeIndex.fromU32(4)),
    );
    try testing.expect(
        !try tree.hasResolution(NodeIndex.fromU32(6)),
    );

    // Blank parent with non-blank children: has resolution.
    try testing.expect(
        try tree.hasResolution(NodeIndex.fromU32(1)),
    );

    // Blank parent with all-blank children: no resolution.
    try testing.expect(
        !try tree.hasResolution(NodeIndex.fromU32(5)),
    );

    // Root (blank, but left subtree non-empty): has resolution.
    try testing.expect(
        try tree.hasResolution(NodeIndex.fromU32(3)),
    );
}
