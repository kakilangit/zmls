// Fuzz targets for ratchet tree operations.
//
// Property: random sequences of add/remove on a RatchetTree
// must never corrupt internal invariants (no panics, no OOB,
// leaf_count stays consistent with the backing array).
//
// Run with:  zig build test --fuzz

const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const mls = @import("zmls");
const tree_path = mls.tree_path;
const tree_math = mls.tree_math;
const tree_node = mls.tree_node;
const ratchet_tree_mod = mls.ratchet_tree;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const LeafNode = tree_node.LeafNode;
const Credential = mls.credential.Credential;
const LeafIndex = mls.types.LeafIndex;

// ── Helpers ─────────────────────────────────────────────────

/// Build a minimal LeafNode with a unique byte tag.
fn makeLeaf(tag: u8) LeafNode {
    const id: []const u8 = @as(
        [*]const u8,
        @ptrCast(&tag),
    )[0..1];
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

// ── Fuzz: add/remove sequences ──────────────────────────────

const Op = enum(u2) { add, remove_first, remove_last };

fn fuzzTreeOps(_: void, smith: *Smith) anyerror!void {
    const alloc = testing.allocator;
    // Start with 1 leaf (init requires n > 0).
    var tree = RatchetTree.init(alloc, 1) catch return;
    defer tree.deinit();

    // Seed the first leaf so the tree isn't empty.
    tree.setLeaf(
        LeafIndex.fromU32(0),
        makeLeaf(0),
    ) catch return;

    // Track live leaf count separately for validation.
    var live: u32 = 1;
    var next_tag: u8 = 1;

    // Run a bounded sequence of random operations.
    var i: u32 = 0;
    while (i < 64) : (i += 1) {
        if (smith.eosWeightedSimple(7, 1)) break;

        const op = smith.value(Op);
        switch (op) {
            .add => {
                // Protect against OOM in tree extension.
                const li = tree_path.addLeaf(
                    &tree,
                    makeLeaf(next_tag),
                ) catch break;
                _ = li;
                live += 1;
                next_tag +%= 1;
            },
            .remove_first => {
                if (live == 0) continue;
                // Find first occupied leaf.
                var idx: u32 = 0;
                while (idx < tree.leaf_count) : (idx += 1) {
                    const ni = LeafIndex.fromU32(idx)
                        .toNodeIndex();
                    const n = tree.getNode(ni) catch continue;
                    if (n != null) break;
                }
                if (idx >= tree.leaf_count) continue;
                tree_path.removeLeaf(
                    &tree,
                    LeafIndex.fromU32(idx),
                ) catch continue;
                live -= 1;
            },
            .remove_last => {
                if (live == 0) continue;
                // Find last occupied leaf (scan backwards).
                var idx: u32 = tree.leaf_count;
                while (idx > 0) {
                    idx -= 1;
                    const ni = LeafIndex.fromU32(idx)
                        .toNodeIndex();
                    const n = tree.getNode(ni) catch continue;
                    if (n != null) break;
                }
                const ni = LeafIndex.fromU32(idx)
                    .toNodeIndex();
                const chk = tree.getNode(ni) catch continue;
                if (chk == null) continue;
                tree_path.removeLeaf(
                    &tree,
                    LeafIndex.fromU32(idx),
                ) catch continue;
                live -= 1;
            },
        }

        // Invariant: the tree width must match leaf_count.
        if (tree.leaf_count > 0) {
            const expected = tree_math.nodeWidth(
                tree.leaf_count,
            );
            try testing.expectEqual(
                expected,
                tree.nodeCount(),
            );
        }
    }
}

test "fuzz: tree add/remove sequences" {
    try testing.fuzz({}, fuzzTreeOps, .{});
}

// ── Fuzz: tree math ─────────────────────────────────────────

fn fuzzTreeMath(_: void, smith: *Smith) anyerror!void {
    // Pick a leaf count in [1, 512].
    const n = smith.valueRangeAtMost(u32, 1, 512);
    const width = tree_math.nodeWidth(n);

    // root must be in bounds.
    const r = tree_math.root(n);
    try testing.expect(@intFromEnum(r) < width);

    // directPath must not panic for any leaf.
    const leaf_idx = smith.valueRangeAtMost(u32, 0, n - 1);
    const node_idx = leaf_idx * 2; // leaf node index
    var dp_buf: [32]mls.types.NodeIndex = undefined;
    _ = tree_math.directPath(
        @enumFromInt(node_idx),
        n,
        &dp_buf,
    );
}

test "fuzz: tree math" {
    try testing.fuzz({}, fuzzTreeMath, .{});
}
