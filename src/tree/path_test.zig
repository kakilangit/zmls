const std = @import("std");
const testing = std.testing;

const path = @import("path.zig");
const node_mod = @import("node.zig");
const ratchet_tree_mod = @import("ratchet_tree.zig");
const types = @import("../common/types.zig");
const Credential = @import("../credential/credential.zig").Credential;

const HPKECiphertext = path.HPKECiphertext;
const UpdatePathNode = path.UpdatePathNode;
const UpdatePath = path.UpdatePath;
const max_path_nodes = path.max_path_nodes;
const addLeaf = path.addLeaf;
const removeLeaf = path.removeLeaf;
const generateUpdatePath = path.generateUpdatePath;
const applyUpdatePath = path.applyUpdatePath;
const derivePathSecrets = path.derivePathSecrets;
const deriveCommitSecret = path.deriveCommitSecret;
const deriveNodeKeypair = path.deriveNodeKeypair;
const encryptPathSecretTo = path.encryptPathSecretTo;
const decryptPathSecretFrom = path.decryptPathSecretFrom;
const nodePublicKey = path.nodePublicKey;

const NodeIndex = types.NodeIndex;
const LeafIndex = types.LeafIndex;
const Node = node_mod.Node;
const LeafNode = node_mod.LeafNode;
const RatchetTree = ratchet_tree_mod.RatchetTree;

const Default =
    @import("../crypto/default.zig")
        .DhKemX25519Sha256Aes128GcmEd25519;

// -- Test helpers ------------------------------------------------------------

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

/// Create a minimal test LeafNode with the given identity and
/// /// HPKE public key.
fn makeTestLeafWithPk(
    id: []const u8,
    pk: []const u8,
) LeafNode {
    return .{
        .encryption_key = pk,
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

/// Free only the heap-allocated nodes of a GeneratePathResult.
/// Does NOT free the leaf_node (which is caller-owned).
fn deinitGeneratedNodes(
    allocator: std.mem.Allocator,
    nodes: []const UpdatePathNode,
) void {
    for (nodes) |*n| {
        @constCast(n).deinit(allocator);
    }
    if (nodes.len > 0) {
        allocator.free(nodes);
    }
}

// -- Tests -------------------------------------------------------------------

test "HPKECiphertext round-trip" {
    const alloc = testing.allocator;

    const ct = HPKECiphertext{
        .kem_output = &[_]u8{ 0x01, 0x02, 0x03 },
        .ciphertext = &[_]u8{ 0x0A, 0x0B },
    };

    var buf: [64]u8 = undefined;
    const end = try ct.encode(&buf, 0);

    var decoded_r = try HPKECiphertext.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        ct.kem_output,
        decoded_r.value.kem_output,
    );
    try testing.expectEqualSlices(
        u8,
        ct.ciphertext,
        decoded_r.value.ciphertext,
    );
    try testing.expectEqual(end, decoded_r.pos);
}

test "UpdatePathNode round-trip" {
    const alloc = testing.allocator;

    const ct1 = HPKECiphertext{
        .kem_output = &[_]u8{0x11},
        .ciphertext = &[_]u8{0x22},
    };
    const cts = [_]HPKECiphertext{ct1};

    const upn = UpdatePathNode{
        .encryption_key = &[_]u8{ 0xAA, 0xBB },
        .encrypted_path_secret = &cts,
    };

    var buf: [256]u8 = undefined;
    const end = try upn.encode(&buf, 0);

    var decoded_r = try UpdatePathNode.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        upn.encryption_key,
        decoded_r.value.encryption_key,
    );
    try testing.expectEqual(
        @as(usize, 1),
        decoded_r.value.encrypted_path_secret.len,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0x11},
        decoded_r.value.encrypted_path_secret[0].kem_output,
    );
}

test "UpdatePath round-trip" {
    const alloc = testing.allocator;

    const ct1 = HPKECiphertext{
        .kem_output = &[_]u8{0x33},
        .ciphertext = &[_]u8{0x44},
    };
    const cts = [_]HPKECiphertext{ct1};
    const upn = UpdatePathNode{
        .encryption_key = &[_]u8{0xCC},
        .encrypted_path_secret = &cts,
    };
    const nodes = [_]UpdatePathNode{upn};

    const up = UpdatePath{
        .leaf_node = makeTestLeaf("dave"),
        .nodes = &nodes,
    };

    var buf: [1024]u8 = undefined;
    const end = try up.encode(&buf, 0);

    var decoded_r = try UpdatePath.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        "dave",
        decoded_r.value.leaf_node.credential.payload.basic,
    );
    try testing.expectEqual(
        @as(usize, 1),
        decoded_r.value.nodes.len,
    );
    try testing.expectEqual(end, decoded_r.pos);
}

test "addLeaf fills blank slot" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    // Set leaves 0 and 2.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeaf("c"),
    );

    // Add should fill leaf 1 (leftmost blank).
    const index = try addLeaf(&tree, makeTestLeaf("b"));
    try testing.expectEqual(@as(u32, 1), index.toU32());

    const got = try tree.getLeaf(LeafIndex.fromU32(1));
    try testing.expect(got != null);
    try testing.expectEqualSlices(
        u8,
        "b",
        got.?.encryption_key,
    );
}

test "addLeaf extends tree when full" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    // Fill both leaves.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("b"),
    );

    // Add should extend tree to 3 leaves.
    const index = try addLeaf(&tree, makeTestLeaf("c"));
    try testing.expectEqual(@as(u32, 2), index.toU32());
    try testing.expectEqual(@as(u32, 3), tree.leaf_count);

    // Tree width = nodeWidth(3) = 7 (padded to 4-leaf tree).
    try testing.expectEqual(@as(u32, 7), tree.nodeCount());
}

test "removeLeaf blanks leaf and direct path" {
    const alloc = testing.allocator;
    // 4-leaf tree: nodes 0,1,2,3,4,5,6.
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("b"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeaf("c"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(3),
        makeTestLeaf("d"),
    );

    // Set parent nodes.
    try tree.setNode(
        NodeIndex.fromU32(1),
        Node.initParent(.{
            .encryption_key = "pk1",
            .parent_hash = "",
            .unmerged_leaves = &.{},
        }),
    );
    try tree.setNode(
        NodeIndex.fromU32(3),
        Node.initParent(.{
            .encryption_key = "pk3",
            .parent_hash = "",
            .unmerged_leaves = &.{},
        }),
    );

    // Remove leaf 0.
    try removeLeaf(&tree, LeafIndex.fromU32(0));

    // Leaf 0 should be blank.
    const leaf0 = try tree.getLeaf(LeafIndex.fromU32(0));
    try testing.expect(leaf0 == null);

    // Direct path of leaf 0 = [1, 3]. Both should be blank.
    const node1 = try tree.getNode(NodeIndex.fromU32(1));
    try testing.expect(node1 == null);
    const node3 = try tree.getNode(NodeIndex.fromU32(3));
    try testing.expect(node3 == null);

    // Leaf 1, 2, 3 should still be present.
    try testing.expect(
        (try tree.getLeaf(LeafIndex.fromU32(1))) != null,
    );
    try testing.expect(
        (try tree.getLeaf(LeafIndex.fromU32(2))) != null,
    );
    try testing.expect(
        (try tree.getLeaf(LeafIndex.fromU32(3))) != null,
    );
}

test "removeLeaf truncates trailing blanks" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("a"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("b"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(3),
        makeTestLeaf("d"),
    );

    // Remove leaf 3 (rightmost non-blank leaf).
    try removeLeaf(&tree, LeafIndex.fromU32(3));

    // Tree should have been truncated. Leaves 2 and 3 were
    // blank/removed, so the tree should shrink to 2 leaves.
    try testing.expectEqual(@as(u32, 2), tree.leaf_count);
    try testing.expectEqual(@as(u32, 3), tree.nodeCount());
}

// -- Path derivation and generation tests ------------------------------------

test "derivePathSecrets produces deterministic chain" {
    const secret = [_]u8{0x42} ** Default.nh;
    var out1: [max_path_nodes][Default.nh]u8 = undefined;
    var out2: [max_path_nodes][Default.nh]u8 = undefined;

    derivePathSecrets(Default, &secret, 3, &out1);
    derivePathSecrets(Default, &secret, 3, &out2);

    // Deterministic.
    try testing.expectEqualSlices(u8, &out1[0], &out2[0]);
    try testing.expectEqualSlices(u8, &out1[1], &out2[1]);
    try testing.expectEqualSlices(u8, &out1[2], &out2[2]);

    // First element is the input secret.
    try testing.expectEqualSlices(u8, &secret, &out1[0]);

    // Each is different from the previous.
    try testing.expect(
        !std.mem.eql(u8, &out1[0], &out1[1]),
    );
    try testing.expect(
        !std.mem.eql(u8, &out1[1], &out1[2]),
    );
}

test "deriveNodeKeypair produces valid keypair" {
    const secret = [_]u8{0xAA} ** Default.nh;
    const kp = try deriveNodeKeypair(Default, &secret);

    // Public key should be 32 bytes, non-zero.
    try testing.expectEqual(@as(usize, 32), kp.pk.len);
    var all_zero = true;
    for (kp.pk) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "encryptPathSecretTo and decryptPathSecretFrom round-trip" {
    const alloc = testing.allocator;
    const secret = [_]u8{0xBB} ** Default.nh;
    const r_seed = [_]u8{0xCC} ** 32;
    const r_kp = try Default.dhKeypairFromSeed(&r_seed);
    const eph_seed = [_]u8{0xDD} ** 32;
    const group_ctx = "test group context";

    var ct = try encryptPathSecretTo(
        Default,
        alloc,
        &secret,
        &r_kp.pk,
        group_ctx,
        &eph_seed,
    );
    defer ct.deinit(alloc);

    const recovered = try decryptPathSecretFrom(
        Default,
        &ct,
        &r_kp.sk,
        &r_kp.pk,
        group_ctx,
    );

    try testing.expectEqualSlices(u8, &secret, &recovered);
}

test "generateUpdatePath on 4-leaf tree" {
    const alloc = testing.allocator;

    // Build a 4-leaf tree with real DH keys.
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    // Generate keypairs for 4 leaves.
    const seed0 = [_]u8{0x10} ** 32;
    const seed1 = [_]u8{0x20} ** 32;
    const seed2 = [_]u8{0x30} ** 32;
    const seed3 = [_]u8{0x40} ** 32;
    const kp0 = try Default.dhKeypairFromSeed(&seed0);
    const kp1 = try Default.dhKeypairFromSeed(&seed1);
    const kp2 = try Default.dhKeypairFromSeed(&seed2);
    const kp3 = try Default.dhKeypairFromSeed(&seed3);

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafWithPk("alice", &kp0.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafWithPk("bob", &kp1.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeafWithPk("carol", &kp2.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(3),
        makeTestLeafWithPk("dave", &kp3.pk),
    );

    // Sender is leaf 0 (alice). Filtered direct path of leaf 0
    // in a fully populated 4-leaf tree:
    //       3
    //      / \
    //     1   5
    //    / \ / \
    //   0  2 4  6
    // direct path = [1, 3], copath = [2, 5]
    // resolution(2) = {2} (bob's leaf node index is 2)
    // resolution(5) = {4, 6} (carol=4, dave=6)
    // So we need 1 + 2 = 3 eph seeds.
    const eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
        [_]u8{0xE2} ** 32,
        [_]u8{0xE3} ** 32,
    };

    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const group_ctx = "test group context";
    const new_leaf = makeTestLeaf("alice-new");

    const result = try generateUpdatePath(
        Default,
        alloc,
        &tree,
        LeafIndex.fromU32(0),
        new_leaf,
        group_ctx,
        &leaf_secret,
        &eph_seeds,
    );
    defer deinitGeneratedNodes(
        alloc,
        result.update_path.nodes,
    );

    // Should have 2 path nodes.
    try testing.expectEqual(
        @as(usize, 2),
        result.update_path.nodes.len,
    );

    // Node 0: encrypted to 1 member (bob via resolution(2)).
    try testing.expectEqual(
        @as(usize, 1),
        result.update_path.nodes[0]
            .encrypted_path_secret.len,
    );

    // Node 1: encrypted to 2 members (carol, dave via
    // resolution(5)).
    try testing.expectEqual(
        @as(usize, 2),
        result.update_path.nodes[1]
            .encrypted_path_secret.len,
    );

    // Public keys should be 32 bytes each.
    try testing.expectEqual(
        @as(usize, 32),
        result.update_path.nodes[0].encryption_key.len,
    );
    try testing.expectEqual(
        @as(usize, 32),
        result.update_path.nodes[1].encryption_key.len,
    );

    // Commit secret should be non-zero.
    var all_zero = true;
    for (result.commit_secret) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "generateUpdatePath and applyUpdatePath round-trip" {
    const alloc = testing.allocator;

    // Build a 4-leaf tree with real DH keys.
    var tree_sender = try RatchetTree.init(alloc, 4);
    defer tree_sender.deinit();

    const seed0 = [_]u8{0x10} ** 32;
    const seed1 = [_]u8{0x20} ** 32;
    const seed2 = [_]u8{0x30} ** 32;
    const seed3 = [_]u8{0x40} ** 32;
    const kp0 = try Default.dhKeypairFromSeed(&seed0);
    const kp1 = try Default.dhKeypairFromSeed(&seed1);
    const kp2 = try Default.dhKeypairFromSeed(&seed2);
    const kp3 = try Default.dhKeypairFromSeed(&seed3);

    try tree_sender.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafWithPk("alice", &kp0.pk),
    );
    try tree_sender.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafWithPk("bob", &kp1.pk),
    );
    try tree_sender.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeafWithPk("carol", &kp2.pk),
    );
    try tree_sender.setLeaf(
        LeafIndex.fromU32(3),
        makeTestLeafWithPk("dave", &kp3.pk),
    );

    // Generate path from sender (leaf 0).
    const eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
        [_]u8{0xE2} ** 32,
        [_]u8{0xE3} ** 32,
    };
    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const group_ctx = "test group context";
    const new_leaf = makeTestLeaf("alice-new");

    var gen_result = try generateUpdatePath(
        Default,
        alloc,
        &tree_sender,
        LeafIndex.fromU32(0),
        new_leaf,
        group_ctx,
        &leaf_secret,
        &eph_seeds,
    );
    defer deinitGeneratedNodes(
        alloc,
        gen_result.update_path.nodes,
    );

    // Bob (leaf 1) applies the update path. Bob needs a copy of
    // the sender's tree (before the update).
    var tree_bob = try tree_sender.clone();
    defer tree_bob.deinit();

    const apply_result = try applyUpdatePath(
        Default,
        &tree_bob,
        LeafIndex.fromU32(0),
        LeafIndex.fromU32(1),
        &gen_result.update_path,
        group_ctx,
        &kp1.sk,
        &kp1.pk,
    );

    // Both sides should derive the same commit_secret.
    try testing.expectEqualSlices(
        u8,
        &gen_result.commit_secret,
        &apply_result.commit_secret,
    );
}

test "generateUpdatePath and applyUpdatePath: carol decrypts" {
    const alloc = testing.allocator;

    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    const seed0 = [_]u8{0x10} ** 32;
    const seed1 = [_]u8{0x20} ** 32;
    const seed2 = [_]u8{0x30} ** 32;
    const seed3 = [_]u8{0x40} ** 32;
    const kp0 = try Default.dhKeypairFromSeed(&seed0);
    const kp1 = try Default.dhKeypairFromSeed(&seed1);
    const kp2 = try Default.dhKeypairFromSeed(&seed2);
    const kp3 = try Default.dhKeypairFromSeed(&seed3);

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafWithPk("alice", &kp0.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafWithPk("bob", &kp1.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeafWithPk("carol", &kp2.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(3),
        makeTestLeafWithPk("dave", &kp3.pk),
    );

    const eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
        [_]u8{0xE2} ** 32,
        [_]u8{0xE3} ** 32,
    };
    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const group_ctx = "test group context";

    var gen_result = try generateUpdatePath(
        Default,
        alloc,
        &tree,
        LeafIndex.fromU32(0),
        makeTestLeaf("alice-new"),
        group_ctx,
        &leaf_secret,
        &eph_seeds,
    );
    defer deinitGeneratedNodes(
        alloc,
        gen_result.update_path.nodes,
    );

    // Carol (leaf 2) applies the update path.
    var tree_carol = try tree.clone();
    defer tree_carol.deinit();

    const apply_result = try applyUpdatePath(
        Default,
        &tree_carol,
        LeafIndex.fromU32(0),
        LeafIndex.fromU32(2),
        &gen_result.update_path,
        group_ctx,
        &kp2.sk,
        &kp2.pk,
    );

    // Same commit_secret as sender.
    try testing.expectEqualSlices(
        u8,
        &gen_result.commit_secret,
        &apply_result.commit_secret,
    );
}

test "deriveCommitSecret differs from last path secret" {
    const secret = [_]u8{0x55} ** Default.nh;
    const cs = deriveCommitSecret(Default, &secret);
    try testing.expect(
        !std.mem.eql(u8, &secret, &cs),
    );
}

test "nodePublicKey extracts from leaf and parent" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    const seed = [_]u8{0x10} ** 32;
    const kp = try Default.dhKeypairFromSeed(&seed);

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafWithPk("a", &kp.pk),
    );

    const pk = try nodePublicKey(
        Default,
        &tree,
        NodeIndex.fromU32(0),
    );
    try testing.expectEqualSlices(u8, &kp.pk, &pk);

    // Parent node.
    try tree.setNode(
        NodeIndex.fromU32(1),
        Node.initParent(.{
            .encryption_key = &kp.pk,
            .parent_hash = "",
            .unmerged_leaves = &.{},
        }),
    );
    const ppk = try nodePublicKey(
        Default,
        &tree,
        NodeIndex.fromU32(1),
    );
    try testing.expectEqualSlices(u8, &kp.pk, &ppk);
}

test "nodePublicKey returns error for blank node" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    const result = nodePublicKey(
        Default,
        &tree,
        NodeIndex.fromU32(0),
    );
    try testing.expectError(error.BlankNode, result);
}

// -- Unmerged leaves HPKE tests (Phase 13.4) --

// Tree layout for 4 leaves:
//
//          3 (root)
//         / \
//        1   5
//       / \ / \
//      0  2 4  6
//
// Leaf indices: 0,1,2,3 → node indices: 0,2,4,6.
// Sender = leaf 0. Direct path = [1,3], copath = [2,5].
// Node 5 is a non-blank parent with unmerged_leaves=[leaf 3].
// Resolution of node 2 (leaf 1) = [node 2] → 1 ciphertext.
// Resolution of node 5 = [node 5, node 6] → 2 ciphertexts.
// Total eph_seeds needed: 3.

test "generateUpdatePath: unmerged leaf creates extra ciphertext" {
    const alloc = testing.allocator;

    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    // Leaf keys.
    const seed0 = [_]u8{0x10} ** 32;
    const seed1 = [_]u8{0x20} ** 32;
    const seed2 = [_]u8{0x30} ** 32;
    const seed3 = [_]u8{0x40} ** 32;
    const kp0 = try Default.dhKeypairFromSeed(&seed0);
    const kp1 = try Default.dhKeypairFromSeed(&seed1);
    const kp2 = try Default.dhKeypairFromSeed(&seed2);
    const kp3 = try Default.dhKeypairFromSeed(&seed3);

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafWithPk("alice", &kp0.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafWithPk("bob", &kp1.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeafWithPk("carol", &kp2.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(3),
        makeTestLeafWithPk("dave", &kp3.pk),
    );

    // Parent node 5 with unmerged_leaves=[leaf 3].
    // Use kp2's pk as parent encryption key (simulates a key
    // that leaf 2 holds but leaf 3 does not, since leaf 3 is
    // unmerged).
    const parent_seed = [_]u8{0x50} ** 32;
    const parent_kp = try Default.dhKeypairFromSeed(&parent_seed);
    const ul = [_]LeafIndex{LeafIndex.fromU32(3)};
    try tree.setNode(
        NodeIndex.fromU32(5),
        Node.initParent(.{
            .encryption_key = &parent_kp.pk,
            .parent_hash = "",
            .unmerged_leaves = &ul,
        }),
    );

    // 3 eph_seeds: 1 for resolution(node 2) + 2 for
    // resolution(node 5).
    const eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
        [_]u8{0xE2} ** 32,
        [_]u8{0xE3} ** 32,
    };
    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const group_ctx = "test group context";

    const gen = try generateUpdatePath(
        Default,
        alloc,
        &tree,
        LeafIndex.fromU32(0),
        makeTestLeaf("alice-new"),
        group_ctx,
        &leaf_secret,
        &eph_seeds,
    );
    defer deinitGeneratedNodes(alloc, gen.update_path.nodes);

    // Nodes[0] encrypts to resolution(copath[0] = node 2).
    // Node 2 is leaf 1 → resolution = [node 2] → 1 ciphertext.
    try testing.expectEqual(
        @as(usize, 1),
        gen.update_path.nodes[0].encrypted_path_secret.len,
    );
    // Nodes[1] encrypts to resolution(copath[1] = node 5).
    // Node 5 is parent with unmerged leaf 3 → resolution =
    // [node 5, node 6] → 2 ciphertexts.
    try testing.expectEqual(
        @as(usize, 2),
        gen.update_path.nodes[1].encrypted_path_secret.len,
    );
}

test "applyUpdatePath: unmerged leaf decrypts with own key" {
    const alloc = testing.allocator;

    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    const seed0 = [_]u8{0x10} ** 32;
    const seed1 = [_]u8{0x20} ** 32;
    const seed2 = [_]u8{0x30} ** 32;
    const seed3 = [_]u8{0x40} ** 32;
    const kp0 = try Default.dhKeypairFromSeed(&seed0);
    const kp1 = try Default.dhKeypairFromSeed(&seed1);
    const kp2 = try Default.dhKeypairFromSeed(&seed2);
    const kp3 = try Default.dhKeypairFromSeed(&seed3);

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafWithPk("alice", &kp0.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafWithPk("bob", &kp1.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeafWithPk("carol", &kp2.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(3),
        makeTestLeafWithPk("dave", &kp3.pk),
    );

    // Parent node 5 with unmerged_leaves=[leaf 3].
    const parent_seed = [_]u8{0x50} ** 32;
    const parent_kp = try Default.dhKeypairFromSeed(&parent_seed);
    const ul = [_]LeafIndex{LeafIndex.fromU32(3)};
    try tree.setNode(
        NodeIndex.fromU32(5),
        Node.initParent(.{
            .encryption_key = &parent_kp.pk,
            .parent_hash = "",
            .unmerged_leaves = &ul,
        }),
    );

    const eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
        [_]u8{0xE2} ** 32,
        [_]u8{0xE3} ** 32,
    };
    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const group_ctx = "test group context";

    // Generate from leaf 0.
    const gen = try generateUpdatePath(
        Default,
        alloc,
        &tree,
        LeafIndex.fromU32(0),
        makeTestLeaf("alice-new"),
        group_ctx,
        &leaf_secret,
        &eph_seeds,
    );
    defer deinitGeneratedNodes(alloc, gen.update_path.nodes);

    // Dave (leaf 3, unmerged under node 5) applies path using
    // his own leaf key.
    var tree_dave = try tree.clone();
    defer tree_dave.deinit();

    const apply_result = try applyUpdatePath(
        Default,
        &tree_dave,
        LeafIndex.fromU32(0),
        LeafIndex.fromU32(3),
        &gen.update_path,
        group_ctx,
        &kp3.sk,
        &kp3.pk,
    );

    // Commit secret must match the sender's.
    try testing.expectEqualSlices(
        u8,
        &gen.commit_secret,
        &apply_result.commit_secret,
    );
}
