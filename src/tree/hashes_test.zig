const std = @import("std");
const testing = std.testing;

const hashes = @import("hashes.zig");
const tree_math = @import("math.zig");
const node_mod = @import("node.zig");
const ratchet_tree_mod = @import("ratchet_tree.zig");
const types = @import("../common/types.zig");
const Credential = @import("../credential/credential.zig").Credential;

const NodeIndex = types.NodeIndex;
const LeafIndex = types.LeafIndex;
const Node = node_mod.Node;
const LeafNode = node_mod.LeafNode;
const ParentNode = node_mod.ParentNode;
const RatchetTree = ratchet_tree_mod.RatchetTree;

const TestCrypto = @import("../crypto/default.zig")
    .DhKemX25519Sha256Aes128GcmEd25519;

const treeHash = hashes.treeHash;
const parentHash = hashes.parentHash;

fn makeTestLeaf(id: []const u8) LeafNode {
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

fn makeTestParent(key: []const u8, ph: []const u8) ParentNode {
    return .{
        .encryption_key = key,
        .parent_hash = ph,
        .unmerged_leaves = &.{},
    };
}

test "tree hash of single leaf tree" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 1);
    defer tree.deinit();

    // Set a leaf node.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );

    const h = try treeHash(
        TestCrypto,
        testing.allocator,
        &tree,
        tree_math.root(tree.leaf_count),
    );

    // Should produce a non-zero 32-byte hash.
    var all_zero = true;
    for (h) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "tree hash of blank tree" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    // All blank — should still produce a valid hash.
    const h = try treeHash(
        TestCrypto,
        testing.allocator,
        &tree,
        tree_math.root(tree.leaf_count),
    );

    var all_zero = true;
    for (h) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "tree hash is deterministic" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeaf("carol"),
    );

    const h1 = try treeHash(
        TestCrypto,
        testing.allocator,
        &tree,
        tree_math.root(tree.leaf_count),
    );
    const h2 = try treeHash(
        TestCrypto,
        testing.allocator,
        &tree,
        tree_math.root(tree.leaf_count),
    );

    try testing.expectEqualSlices(u8, &h1, &h2);
}

test "tree hash changes when tree changes" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );

    const h1 = try treeHash(
        TestCrypto,
        testing.allocator,
        &tree,
        tree_math.root(tree.leaf_count),
    );

    // Modify the tree.
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );

    const h2 = try treeHash(
        TestCrypto,
        testing.allocator,
        &tree,
        tree_math.root(tree.leaf_count),
    );

    // Hashes must differ.
    try testing.expect(!std.mem.eql(u8, &h1, &h2));
}

test "parent hash computation" {
    const alloc = testing.allocator;
    // 2-leaf tree: nodes 0, 1, 2. Root at 1.
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );

    // Set a parent node at index 1 (root).
    try tree.setNode(
        NodeIndex.fromU32(1),
        Node.initParent(makeTestParent("pk", "")),
    );

    // Compute tree hash of the sibling (node 2 = leaf "bob").
    const sibling_hash = try treeHash(
        TestCrypto,
        testing.allocator,
        &tree,
        NodeIndex.fromU32(2),
    );

    const ph = try parentHash(
        TestCrypto,
        &tree,
        NodeIndex.fromU32(1),
        &sibling_hash,
    );

    // Should produce a non-zero hash.
    var all_zero = true;
    for (ph) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);

    // Deterministic.
    const ph2 = try parentHash(
        TestCrypto,
        &tree,
        NodeIndex.fromU32(1),
        &sibling_hash,
    );
    try testing.expectEqualSlices(u8, &ph, &ph2);
}

test "parent hash changes with different sibling hash" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setNode(
        NodeIndex.fromU32(1),
        Node.initParent(makeTestParent("pk", "")),
    );

    const sh1 = [_]u8{0x01} ** TestCrypto.nh;
    const sh2 = [_]u8{0x02} ** TestCrypto.nh;

    const ph1 = try parentHash(
        TestCrypto,
        &tree,
        NodeIndex.fromU32(1),
        &sh1,
    );
    const ph2 = try parentHash(
        TestCrypto,
        &tree,
        NodeIndex.fromU32(1),
        &sh2,
    );

    try testing.expect(!std.mem.eql(u8, &ph1, &ph2));
}

test "parent hash rejects blank node" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    const sh = [_]u8{0x00} ** TestCrypto.nh;
    const result = parentHash(
        TestCrypto,
        &tree,
        NodeIndex.fromU32(1), // blank
        &sh,
    );
    try testing.expectError(error.BlankNode, result);
}
