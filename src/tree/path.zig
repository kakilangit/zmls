//! UpdatePath wire format and tree mutation operations (addLeaf,
//! removeLeaf, applyUpdatePath) per RFC 9420 Sections 7.4-7.5.
// Tree evolution: UpdatePath, add/remove leaf, and path application.
//
// Per RFC 9420 Sections 7.4-7.5: an UpdatePath carries new keying
// material along a sender's direct path. Each node on the filtered
// direct path gets a new encryption key and the path secret is
// HPKE-encrypted to each resolution member of the corresponding
// copath node.
//
// This module defines the wire-format structs (HPKECiphertext,
// UpdatePathNode, UpdatePath) and tree mutation operations
// (addLeaf, removeLeaf, applyUpdatePath).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const tree_math = @import("math.zig");
const node_mod = @import("node.zig");
const ratchet_tree_mod = @import("ratchet_tree.zig");

const NodeIndex = types.NodeIndex;
const LeafIndex = types.LeafIndex;
const TreeError = errors.TreeError;
const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const Node = node_mod.Node;
const LeafNode = node_mod.LeafNode;
const ParentNode = node_mod.ParentNode;
const RatchetTree = ratchet_tree_mod.RatchetTree;

/// Maximum number of HPKE ciphertexts per UpdatePathNode.
const max_ciphertexts: u32 = 1024;

/// Maximum number of UpdatePathNodes in an UpdatePath.
pub const max_path_nodes: u32 = 32;

/// Maximum encoded size for HPKE ciphertext components.
const max_ct_data: u32 = 8192;

// -- HPKECiphertext (Section 7.6) -------------------------------------------

/// An HPKE ciphertext: KEM output + encrypted payload.
///
///   struct {
///       opaque kem_output<V>;
///       opaque ciphertext<V>;
///   } HPKECiphertext;
pub const HPKECiphertext = struct {
    kem_output: []const u8,
    ciphertext: []const u8,

    pub fn encode(
        self: *const HPKECiphertext,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeVarVector(
            buf,
            pos,
            self.kem_output,
        );
        p = try codec.encodeVarVector(
            buf,
            p,
            self.ciphertext,
        );
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: HPKECiphertext,
        pos: u32,
    } {
        const kem_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            pos,
            types.max_public_key_length,
        );
        const ct_r = try codec.decodeVarVector(
            allocator,
            data,
            kem_r.pos,
        );
        return .{
            .value = .{
                .kem_output = kem_r.value,
                .ciphertext = ct_r.value,
            },
            .pos = ct_r.pos,
        };
    }

    pub fn deinit(
        self: *HPKECiphertext,
        allocator: std.mem.Allocator,
    ) void {
        if (self.kem_output.len > 0) {
            allocator.free(self.kem_output);
        }
        if (self.ciphertext.len > 0) {
            allocator.free(self.ciphertext);
        }
        self.* = undefined;
    }
};

// -- UpdatePathNode (Section 7.6) -------------------------------------------

/// A node in an UpdatePath: new encryption key + encrypted path
/// secrets for the copath resolution.
///
///   struct {
///       HPKEPublicKey encryption_key;
///       HPKECiphertext encrypted_path_secret<V>;
///   } UpdatePathNode;
pub const UpdatePathNode = struct {
    encryption_key: []const u8,
    encrypted_path_secret: []const HPKECiphertext,

    pub fn encode(
        self: *const UpdatePathNode,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeVarVector(
            buf,
            pos,
            self.encryption_key,
        );
        // encrypted_path_secret<V>: varint-prefixed list.
        p = try encodeHpkeCiphertextList(
            buf,
            p,
            self.encrypted_path_secret,
        );
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: UpdatePathNode,
        pos: u32,
    } {
        const ek_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            pos,
            types.max_public_key_length,
        );
        const ct_r = try decodeHpkeCiphertextList(
            allocator,
            data,
            ek_r.pos,
        );
        return .{
            .value = .{
                .encryption_key = ek_r.value,
                .encrypted_path_secret = ct_r.value,
            },
            .pos = ct_r.pos,
        };
    }

    pub fn deinit(
        self: *UpdatePathNode,
        allocator: std.mem.Allocator,
    ) void {
        if (self.encryption_key.len > 0) {
            allocator.free(self.encryption_key);
        }
        for (self.encrypted_path_secret) |*ct| {
            @constCast(ct).deinit(allocator);
        }
        if (self.encrypted_path_secret.len > 0) {
            allocator.free(self.encrypted_path_secret);
        }
        self.* = undefined;
    }
};

// -- UpdatePath (Section 7.5) -----------------------------------------------

/// An update path: new leaf + path nodes along the filtered direct
/// path.
///
///   struct {
///       LeafNode leaf_node;
///       UpdatePathNode nodes<V>;
///   } UpdatePath;
pub const UpdatePath = struct {
    leaf_node: LeafNode,
    nodes: []const UpdatePathNode,

    pub fn encode(
        self: *const UpdatePath,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try self.leaf_node.encode(buf, pos);
        p = try encodeUpdatePathNodeList(buf, p, self.nodes);
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: UpdatePath,
        pos: u32,
    } {
        const leaf_r = try LeafNode.decode(
            allocator,
            data,
            pos,
        );
        const nodes_r = try decodeUpdatePathNodeList(
            allocator,
            data,
            leaf_r.pos,
        );
        return .{
            .value = .{
                .leaf_node = leaf_r.value,
                .nodes = nodes_r.value,
            },
            .pos = nodes_r.pos,
        };
    }

    pub fn deinit(
        self: *UpdatePath,
        allocator: std.mem.Allocator,
    ) void {
        self.leaf_node.deinit(allocator);
        for (self.nodes) |*n| {
            @constCast(n).deinit(allocator);
        }
        if (self.nodes.len > 0) {
            allocator.free(self.nodes);
        }
        self.* = undefined;
    }
};

// -- Tree Mutation Operations -----------------------------------------------

/// Add a leaf to the tree. Per RFC 9420 Section 7.7:
///   - Find the leftmost blank leaf.
///   - If none, extend the tree by one leaf.
///
/// Returns the LeafIndex of the added leaf.
///
/// NOTE: This function only handles the simple case of adding to
/// an existing tree. It does NOT reallocate the tree array (the
/// caller must ensure the tree has capacity or handle extension
/// externally). If no blank leaf exists and the tree cannot grow,
/// returns EmptyTree error.
pub fn addLeaf(
    tree: *RatchetTree,
    leaf: LeafNode,
) (TreeError || error{OutOfMemory})!LeafIndex {
    assert(tree.leaf_count > 0);
    // Search for leftmost blank leaf.
    var li: u32 = 0;
    while (li < tree.leaf_count) : (li += 1) {
        const index = LeafIndex.fromU32(li);
        const node = try tree.getNode(index.toNodeIndex());
        if (node == null) {
            // Found a blank leaf — use it.
            try tree.setLeaf(index, leaf);
            try addToUnmergedLists(tree, index);
            return index;
        }
    }

    // No blank leaf found. Extend the tree.
    const index = try extendAndAdd(tree, leaf);
    try addToUnmergedLists(tree, index);
    return index;
}

/// Per RFC 9420 Section 7.7: for each non-blank intermediate
/// node on the new leaf's direct path, add the leaf index to
/// that node's unmerged_leaves list.
fn addToUnmergedLists(
    tree: *RatchetTree,
    new_leaf: LeafIndex,
) (TreeError || error{OutOfMemory})!void {
    var dp_buf: [32]NodeIndex = undefined;
    const dp = tree_math.directPath(
        new_leaf.toNodeIndex(),
        tree.leaf_count,
        &dp_buf,
    );
    for (dp) |ancestor| {
        const index = ancestor.toUsize();
        if (index >= tree.nodes.len) continue;
        if (tree.nodes[index] == null) continue;
        if (tree.nodes[index].?.node_type != .parent) continue;

        const old_ul =
            tree.nodes[index].?.payload.parent.unmerged_leaves;
        const old_len: u32 = @intCast(old_ul.len);
        const new_len = old_len + 1;
        const new_ul = tree.allocator.alloc(
            LeafIndex,
            new_len,
        ) catch return error.OutOfMemory;

        // Insert in sorted order per RFC 9420 Section 7.1.
        const new_val = new_leaf.toU32();
        var ins: u32 = old_len;
        for (old_ul, 0..) |entry, j| {
            if (entry.toU32() >= new_val) {
                ins = @intCast(j);
                break;
            }
        }
        if (ins > 0) @memcpy(new_ul[0..ins], old_ul[0..ins]);
        new_ul[ins] = new_leaf;
        if (ins < old_len) {
            @memcpy(
                new_ul[ins + 1 .. new_len],
                old_ul[ins..old_len],
            );
        }

        // Free old unmerged_leaves if tree owns contents.
        if (tree.owns_contents and old_len > 0) {
            tree.allocator.free(old_ul);
        }
        // Update in-place through the nodes slice.
        tree.nodes[index].?.payload.parent.unmerged_leaves =
            new_ul;
    }
}

/// Extend the tree by one leaf and add the given leaf node.
fn extendAndAdd(
    tree: *RatchetTree,
    leaf: LeafNode,
) (TreeError || error{OutOfMemory})!LeafIndex {
    const new_leaf_count = tree.leaf_count + 1;
    const new_width = tree_math.nodeWidth(new_leaf_count);
    const old_width = tree.nodeCount();

    // Grow the backing array.
    const new_nodes = try tree.allocator.realloc(
        tree.nodes,
        new_width,
    );

    // Zero-init new entries.
    @memset(new_nodes[old_width..new_width], null);

    tree.nodes = new_nodes;
    tree.leaf_count = new_leaf_count;

    // Place the leaf.
    const new_li = LeafIndex.fromU32(new_leaf_count - 1);
    try tree.setLeaf(new_li, leaf);

    return new_li;
}

/// Remove a leaf from the tree. Per RFC 9420 Section 7.7:
///   1. Blank the leaf node.
///   2. Blank all nodes on the leaf's direct path.
///   3. Remove the leaf from all surviving parent nodes'
///      unmerged_leaves lists.
///   4. Truncate the tree: remove trailing blank leaves.
pub fn removeLeaf(
    tree: *RatchetTree,
    leaf: LeafIndex,
) (TreeError || error{OutOfMemory})!void {
    assert(tree.leaf_count > 1);
    if (leaf.toU32() >= tree.leaf_count) {
        return error.IndexOutOfRange;
    }

    // 1. Blank the leaf.
    try tree.blankNode(leaf.toNodeIndex());

    // 2. Blank the direct path.
    var dp_buf: [32]NodeIndex = undefined;
    const dp = tree_math.directPath(
        leaf.toNodeIndex(),
        tree.leaf_count,
        &dp_buf,
    );
    for (dp) |ancestor| {
        try tree.blankNode(ancestor);
    }

    // 3. Remove the leaf from all surviving parent nodes'
    //    unmerged_leaves lists.
    try removeFromAllUnmergedLists(tree, leaf);

    // 4. Truncate trailing blank leaves.
    truncateTree(tree);
}

/// Remove `leaf` from every surviving parent node's
/// unmerged_leaves list. Called during removeLeaf to clean
/// parent nodes NOT on the removed leaf's direct path
/// (direct-path parents are already blanked).
fn removeFromAllUnmergedLists(
    tree: *RatchetTree,
    leaf: LeafIndex,
) error{OutOfMemory}!void {
    const width = tree.nodeCount();
    var ni: u32 = 1; // skip node 0 (leaf); step by 2 = parents
    while (ni < width) : (ni += 2) {
        const node_opt = &tree.nodes[ni];
        if (node_opt.* == null) continue;
        if (node_opt.*.?.node_type != .parent) continue;
        const pn = &node_opt.*.?.payload.parent;
        const ul = pn.unmerged_leaves;
        const pos = findLeafInSlice(ul, leaf);
        if (pos == null) continue;
        const p = pos.?;
        const old_len: u32 = @intCast(ul.len);
        if (old_len == 1) {
            if (tree.owns_contents) tree.allocator.free(ul);
            pn.unmerged_leaves = &.{};
            continue;
        }
        const new = tree.allocator.alloc(
            LeafIndex,
            old_len - 1,
        ) catch return error.OutOfMemory;
        if (p > 0) @memcpy(new[0..p], ul[0..p]);
        const rest = old_len - p - 1;
        if (rest > 0) @memcpy(new[p .. p + rest], ul[p + 1 ..]);
        if (tree.owns_contents) tree.allocator.free(ul);
        pn.unmerged_leaves = new;
    }
}

/// Find `leaf` in a sorted unmerged_leaves slice.
fn findLeafInSlice(
    ul: []const LeafIndex,
    leaf: LeafIndex,
) ?u32 {
    const val = leaf.toU32();
    for (ul, 0..) |entry, i| {
        if (entry.toU32() == val) return @intCast(i);
        if (entry.toU32() > val) return null;
    }
    return null;
}

/// Blank intermediate nodes along a leaf's direct path.
///
/// Per RFC 9420 Section 12.1.2: when applying an Update proposal,
/// blank the intermediate nodes along the path from the sender's
/// leaf to the root. Does NOT blank the leaf itself.
pub fn blankDirectPath(
    tree: *RatchetTree,
    leaf: LeafIndex,
) (TreeError || error{OutOfMemory})!void {
    if (leaf.toU32() >= tree.leaf_count) {
        return error.IndexOutOfRange;
    }

    var dp_buf: [32]NodeIndex = undefined;
    const dp = tree_math.directPath(
        leaf.toNodeIndex(),
        tree.leaf_count,
        &dp_buf,
    );
    for (dp) |ancestor| {
        try tree.blankNode(ancestor);
    }
}

/// Remove trailing blank leaves and shrink the tree array.
fn truncateTree(tree: *RatchetTree) void {
    // Find the rightmost non-blank leaf.
    var last_non_blank: u32 = 0;
    var found = false;
    var li: u32 = tree.leaf_count;
    while (li > 0) {
        li -= 1;
        const ni = LeafIndex.fromU32(li).toNodeIndex();
        if (tree.nodes[ni.toUsize()] != null) {
            last_non_blank = li;
            found = true;
            break;
        }
    }

    if (!found) {
        // All leaves are blank — keep at least 1 leaf.
        last_non_blank = 0;
    }

    const new_leaf_count = last_non_blank + 1;
    if (new_leaf_count >= tree.leaf_count) return;

    const new_width = tree_math.nodeWidth(new_leaf_count);

    // Shrink: try to resize in place, otherwise just narrow
    // the slice. The allocator retains ownership of the full
    // allocation, which is freed in deinit.
    if (tree.allocator.resize(tree.nodes, new_width)) {
        tree.nodes.len = new_width;
    } else {
        // Cannot resize in place (e.g. testing allocator).
        // Allocate a smaller buffer and copy.
        const new_nodes = tree.allocator.alloc(
            ?Node,
            new_width,
        ) catch {
            // If allocation fails, just keep the old buffer.
            tree.leaf_count = new_leaf_count;
            return;
        };
        @memcpy(new_nodes, tree.nodes[0..new_width]);
        tree.allocator.free(tree.nodes);
        tree.nodes = new_nodes;
    }
    tree.leaf_count = new_leaf_count;
}

// -- Codec helpers for list types -------------------------------------------

/// Encode a slice of HPKECiphertext into a varint-length-prefixed
/// /// byte vector.
fn encodeHpkeCiphertextList(
    buf: []u8,
    pos: u32,
    items: []const HPKECiphertext,
) EncodeError!u32 {
    // Gap-then-shift encoding for varint prefix.
    const gap: u32 = 4;
    const start = pos + gap;
    var p = start;

    for (items) |*ct| {
        p = try ct.encode(buf, p);
    }

    const inner_len: u32 = p - start;
    var len_buf: [4]u8 = undefined;
    const len_end = try varint.encode(
        &len_buf,
        0,
        inner_len,
    );

    const dest_start = pos + len_end;
    if (dest_start != start) {
        std.mem.copyForwards(
            u8,
            buf[dest_start..][0..inner_len],
            buf[start..][0..inner_len],
        );
    }
    @memcpy(buf[pos..][0..len_end], len_buf[0..len_end]);

    return dest_start + inner_len;
}

fn decodeHpkeCiphertextList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const HPKECiphertext,
    pos: u32,
} {
    const vr = try varint.decode(data, pos);
    const total_len = vr.value;
    var p = vr.pos;

    if (total_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (p + total_len > data.len) return error.Truncated;

    const end = p + total_len;
    var temp: [max_ciphertexts]HPKECiphertext = undefined;
    var count: u32 = 0;
    errdefer for (temp[0..count]) |*ct| ct.deinit(allocator);

    while (p < end) {
        if (count >= max_ciphertexts) {
            return error.VectorTooLarge;
        }
        const ct_r = try HPKECiphertext.decode(
            allocator,
            data,
            p,
        );
        temp[count] = ct_r.value;
        count += 1;
        p = ct_r.pos;
    }

    if (p != end) return error.Truncated;

    const items = allocator.alloc(
        HPKECiphertext,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(items, temp[0..count]);

    return .{ .value = items, .pos = p };
}

/// Encode a slice of UpdatePathNode into a varint-length-prefixed
/// /// byte vector.
fn encodeUpdatePathNodeList(
    buf: []u8,
    pos: u32,
    items: []const UpdatePathNode,
) EncodeError!u32 {
    const gap: u32 = 4;
    const start = pos + gap;
    var p = start;

    for (items) |*n| {
        p = try n.encode(buf, p);
    }

    const inner_len: u32 = p - start;
    var len_buf: [4]u8 = undefined;
    const len_end = try varint.encode(
        &len_buf,
        0,
        inner_len,
    );

    const dest_start = pos + len_end;
    if (dest_start != start) {
        std.mem.copyForwards(
            u8,
            buf[dest_start..][0..inner_len],
            buf[start..][0..inner_len],
        );
    }
    @memcpy(buf[pos..][0..len_end], len_buf[0..len_end]);

    return dest_start + inner_len;
}

fn decodeUpdatePathNodeList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const UpdatePathNode,
    pos: u32,
} {
    const vr = try varint.decode(data, pos);
    const total_len = vr.value;
    var p = vr.pos;

    if (total_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (p + total_len > data.len) return error.Truncated;

    const end = p + total_len;
    var temp: [max_path_nodes]UpdatePathNode = undefined;
    var count: u32 = 0;
    errdefer for (temp[0..count]) |*n| n.deinit(allocator);

    while (p < end) {
        if (count >= max_path_nodes) {
            return error.VectorTooLarge;
        }
        const n_r = try UpdatePathNode.decode(
            allocator,
            data,
            p,
        );
        temp[count] = n_r.value;
        count += 1;
        p = n_r.pos;
    }

    if (p != end) return error.Truncated;

    const items = allocator.alloc(
        UpdatePathNode,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(items, temp[0..count]);

    return .{ .value = items, .pos = p };
}

// -- Path Secret Derivation (RFC 9420 Section 7.5) --------------------------

const primitives = @import("../crypto/primitives.zig");
const hpke_mod = @import("../crypto/hpke.zig");
const tree_hashes = @import("hashes.zig");
const secureZero = primitives.secureZero;
const CryptoError = errors.CryptoError;

/// Result of generateUpdatePath: the UpdatePath wire struct plus the
/// commit_secret derived from the last path secret.
pub fn GeneratePathResult(comptime P: type) type {
    return struct {
        update_path: UpdatePath,
        commit_secret: [P.nh]u8,
    };
}

/// Derive a chain of path secrets from a leaf secret.
///
/// Per RFC 9420 Section 7.5:
///   path_secret[0] = leaf_secret
///   path_secret[n+1] = DeriveSecret(path_secret[n], "path")
///
/// Returns the number of secrets written (== count).
pub fn derivePathSecrets(
    comptime P: type,
    leaf_secret: *const [P.nh]u8,
    count: u32,
    out: *[max_path_nodes][P.nh]u8,
) void {
    std.debug.assert(count > 0);
    std.debug.assert(count <= max_path_nodes);
    out[0] = leaf_secret.*;
    var i: u32 = 1;
    while (i < count) : (i += 1) {
        out[i] = primitives.deriveSecret(
            P,
            &out[i - 1],
            "path",
        );
    }
}

/// Derive commit_secret from the last path_secret.
///
///   commit_secret = DeriveSecret(path_secret[last], "path")
pub fn deriveCommitSecret(
    comptime P: type,
    last_path_secret: *const [P.nh]u8,
) [P.nh]u8 {
    return primitives.deriveSecret(P, last_path_secret, "path");
}

/// Node keypair result: private and public keys.
pub fn NodeKeypair(comptime P: type) type {
    return struct { sk: [P.nsk]u8, pk: [P.npk]u8 };
}

/// Derive a node keypair from a path secret.
///
/// Per RFC 9420 Section 7.5:
///   node_secret = DeriveSecret(path_secret, "node")
///   (node_priv, node_pub) = KEM.DeriveKeyPair(node_secret)
///
/// KEM.DeriveKeyPair is the HPKE DeriveKeyPair function
/// (RFC 9180 Section 7.1.3), NOT a raw seed derivation.
pub fn deriveNodeKeypair(
    comptime P: type,
    path_secret: *const [P.nh]u8,
) CryptoError!NodeKeypair(P) {
    var node_secret = primitives.deriveSecret(
        P,
        path_secret,
        "node",
    );
    defer secureZero(&node_secret);
    const H = hpke_mod.Hpke(P);
    const raw = try H.deriveKeyPair(&node_secret);
    return .{ .sk = raw.sk, .pk = raw.pk };
}

/// Encrypt a path secret to a single recipient's public key.
///
/// Uses EncryptWithLabel(pk, "UpdatePathNode", group_context, secret).
/// Returns an HPKECiphertext (kem_output || ciphertext || tag).
///
/// The returned slices are heap-allocated; caller must free via deinit.
pub fn encryptPathSecretTo(
    comptime P: type,
    allocator: std.mem.Allocator,
    path_secret: *const [P.nh]u8,
    recipient_pk: *const [P.npk]u8,
    group_context: []const u8,
    eph_seed: *const [32]u8,
) (CryptoError || error{OutOfMemory})!HPKECiphertext {
    var ct_buf: [P.nh]u8 = undefined;
    var tag: [P.nt]u8 = undefined;
    const kem_output = try primitives.encryptWithLabel(
        P,
        recipient_pk,
        "UpdatePathNode",
        group_context,
        path_secret,
        eph_seed,
        &ct_buf,
        &tag,
    );

    // Heap-allocate kem_output and ciphertext||tag.
    const ko = allocator.alloc(
        u8,
        P.npk,
    ) catch return error.OutOfMemory;
    errdefer allocator.free(ko);
    @memcpy(ko, &kem_output);

    const ct_len = P.nh + P.nt;
    const ct = allocator.alloc(
        u8,
        ct_len,
    ) catch return error.OutOfMemory;
    @memcpy(ct[0..P.nh], &ct_buf);
    @memcpy(ct[P.nh..ct_len], &tag);

    return .{ .kem_output = ko, .ciphertext = ct };
}

/// Decrypt a path secret from an HPKECiphertext.
///
/// Uses DecryptWithLabel(sk, pk, "UpdatePathNode", group_context, ...).
pub fn decryptPathSecretFrom(
    comptime P: type,
    ct: *const HPKECiphertext,
    recipient_sk: *const [P.nsk]u8,
    recipient_pk: *const [P.npk]u8,
    group_context: []const u8,
) CryptoError![P.nh]u8 {
    if (ct.kem_output.len != P.npk) return error.HpkeOpenFailed;
    const ct_len = P.nh + P.nt;
    if (ct.ciphertext.len != ct_len) return error.HpkeOpenFailed;

    const kem_out: *const [P.npk]u8 = ct.kem_output[0..P.npk];
    const ciphertext = ct.ciphertext[0..P.nh];
    const tag: *const [P.nt]u8 = ct.ciphertext[P.nh..ct_len];

    var pt_out: [P.nh]u8 = undefined;
    errdefer primitives.secureZero(&pt_out);
    try primitives.decryptWithLabel(
        P,
        recipient_sk,
        recipient_pk,
        "UpdatePathNode",
        group_context,
        kem_out,
        ciphertext,
        tag,
        &pt_out,
    );
    return pt_out;
}

/// Encrypt a path secret to all members in a resolution.
///
/// For each node in the resolution, extracts its public key from the
/// tree and encrypts the path secret to it. Returns allocated slice
/// of HPKECiphertext. eph_seeds[i] provides the deterministic seed
/// for the i-th encryption (for testability).
pub fn encryptToResolution(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    path_secret: *const [P.nh]u8,
    resolution: []const NodeIndex,
    group_context: []const u8,
    eph_seeds: []const [32]u8,
) (CryptoError || TreeError || error{OutOfMemory})![]HPKECiphertext {
    std.debug.assert(resolution.len == eph_seeds.len);

    const cts = allocator.alloc(
        HPKECiphertext,
        resolution.len,
    ) catch return error.OutOfMemory;
    var init_count: u32 = 0;
    errdefer freeCtSlice(allocator, cts, init_count);

    for (resolution, 0..) |node_idx, i| {
        const pk = try nodePublicKey(P, tree, node_idx);
        cts[i] = try encryptPathSecretTo(
            P,
            allocator,
            path_secret,
            &pk,
            group_context,
            &eph_seeds[i],
        );
        init_count += 1;
    }
    return cts;
}

/// Extract the HPKE public key from a tree node.
fn nodePublicKey(
    comptime P: type,
    tree: *const RatchetTree,
    index: NodeIndex,
) (TreeError || CryptoError)![P.npk]u8 {
    const node = try tree.getNode(index);
    if (node == null) return error.BlankNode;
    const n = node.?;
    const ek = switch (n.node_type) {
        .leaf => n.payload.leaf.encryption_key,
        .parent => n.payload.parent.encryption_key,
    };
    if (ek.len != P.npk) return error.InvalidPublicKey;
    var pk: [P.npk]u8 = undefined;
    @memcpy(&pk, ek[0..P.npk]);
    return pk;
}

/// Free a partially-initialized slice of HPKECiphertext.
fn freeCtSlice(
    allocator: std.mem.Allocator,
    cts: []HPKECiphertext,
    count: u32,
) void {
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        cts[i].deinit(allocator);
    }
    allocator.free(cts);
}

/// Result of derivePathKeys: path secrets, public keys, and
/// commit_secret — without HPKE encryption.
pub fn DerivedPathKeys(comptime P: type) type {
    return struct {
        secrets: [max_path_nodes][P.nh]u8,
        public_keys: [max_path_nodes][P.npk]u8,
        commit_secret: [P.nh]u8,
        n_path: u32,

        /// Zero all secret material (path secrets and
        /// commit_secret). Public keys are not zeroed.
        pub fn zeroize(self: *@This()) void {
            for (&self.secrets) |*s| secureZero(s);
            secureZero(&self.commit_secret);
        }
    };
}

/// Derive path secrets and public keys for an UpdatePath.
///
/// This is the first phase of path generation: it derives path
/// secrets from the leaf_secret, computes node keypairs, and
/// returns the commit_secret. No HPKE encryption is performed.
///
/// The caller uses the public keys to build a skeleton
/// UpdatePath (for tree merging), then encrypts path secrets
/// in a second phase after computing the provisional
/// GroupContext.
pub fn derivePathKeys(
    comptime P: type,
    tree: *const RatchetTree,
    sender: LeafIndex,
    leaf_secret: *const [P.nh]u8,
) !DerivedPathKeys(P) {
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);
    if (n_path == 0) return error.EmptyTree;

    var result: DerivedPathKeys(P) = undefined;
    derivePathSecrets(P, leaf_secret, n_path, &result.secrets);

    var i: u32 = 0;
    while (i < n_path) : (i += 1) {
        var kp = try deriveNodeKeypair(P, &result.secrets[i]);
        result.public_keys[i] = kp.pk;
        secureZero(&kp.sk);
    }

    result.commit_secret = deriveCommitSecret(
        P,
        &result.secrets[n_path - 1],
    );
    result.n_path = n_path;
    return result;
}

/// Encrypt path secrets to resolution members for each node
/// on the filtered direct path.
///
/// This is the second phase of path generation: given the
/// derived path secrets, encrypt each one to the copath
/// resolution members using the provisional GroupContext.
///
/// `excluded_leaves` lists leaves added in the same commit.
/// Per RFC 9420 Section 12.4.2, the sender MUST NOT encrypt
/// the path to newly-added members.
///
/// Returns a heap-allocated slice of UpdatePathNode.
pub fn encryptPathNodes(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    sender: LeafIndex,
    secrets: *const [max_path_nodes][P.nh]u8,
    public_keys: *const [max_path_nodes][P.npk]u8,
    n_path: u32,
    group_context: []const u8,
    eph_seeds: []const [32]u8,
    excluded_leaves: []const LeafIndex,
) ![]UpdatePathNode {
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    if (@as(u32, @intCast(fdp.path.len)) != n_path) {
        return error.MalformedUpdatePath;
    }

    const nodes = allocator.alloc(
        UpdatePathNode,
        n_path,
    ) catch return error.OutOfMemory;
    var node_count: u32 = 0;
    errdefer freeUpnSlice(allocator, nodes, node_count);

    var seed_idx: u32 = 0;
    var res_buf: [RatchetTree.max_resolution_size]NodeIndex =
        undefined;
    var filt_buf: [RatchetTree.max_resolution_size]NodeIndex =
        undefined;

    var pi: u32 = 0;
    while (pi < n_path) : (pi += 1) {
        const result = try encryptSinglePathNode(
            P,
            allocator,
            tree,
            &secrets[pi],
            &public_keys[pi],
            fdp.copath[pi],
            group_context,
            eph_seeds,
            excluded_leaves,
            seed_idx,
            &res_buf,
            &filt_buf,
        );
        nodes[pi] = result.node;
        node_count += 1;
        seed_idx += result.n_filt;
    }
    return nodes;
}

const EncryptNodeResult = struct {
    node: UpdatePathNode,
    n_filt: u32,
};

/// Encrypt a single path node: resolve copath, filter excluded
/// leaves, encrypt path secret to the filtered resolution.
fn encryptSinglePathNode(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    secret: *const [P.nh]u8,
    public_key: *const [P.npk]u8,
    copath_node: NodeIndex,
    group_context: []const u8,
    eph_seeds: []const [32]u8,
    excluded_leaves: []const LeafIndex,
    seed_idx: u32,
    res_buf: *[RatchetTree.max_resolution_size]NodeIndex,
    filt_buf: *[RatchetTree.max_resolution_size]NodeIndex,
) !EncryptNodeResult {
    const res = try tree.resolution(
        copath_node,
        res_buf,
    );
    const filtered = filterResolution(
        res,
        filt_buf,
        excluded_leaves,
    );
    const n_filt: u32 = @intCast(filtered.len);
    const seeds_end = seed_idx + n_filt;
    if (seeds_end > eph_seeds.len) {
        return error.MalformedUpdatePath;
    }

    const cts = try encryptToResolution(
        P,
        allocator,
        tree,
        secret,
        filtered,
        group_context,
        eph_seeds[seed_idx..seeds_end],
    );

    const ek = allocator.alloc(
        u8,
        P.npk,
    ) catch return error.OutOfMemory;
    @memcpy(ek, public_key);

    return .{
        .node = .{
            .encryption_key = ek,
            .encrypted_path_secret = cts,
        },
        .n_filt = n_filt,
    };
}

/// Encrypt one path node: derive keypair, encrypt path secret
/// to the resolution of the copath node, return UpdatePathNode.
fn encryptCommitPathNode(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    secret: *const [P.nh]u8,
    copath_node: NodeIndex,
    group_context: []const u8,
    eph_seeds: []const [32]u8,
) !UpdatePathNode {
    var kp = try deriveNodeKeypair(P, secret);
    defer secureZero(&kp.sk);

    var res_buf: [RatchetTree.max_resolution_size]NodeIndex =
        undefined;
    const res = try tree.resolution(copath_node, &res_buf);
    const n_res: u32 = @intCast(res.len);
    if (n_res > eph_seeds.len)
        return error.MalformedUpdatePath;

    const cts = try encryptToResolution(
        P,
        allocator,
        tree,
        secret,
        res,
        group_context,
        eph_seeds[0..n_res],
    );
    errdefer {
        for (cts) |*ct| ct.deinit(allocator);
        allocator.free(cts);
    }

    const ek = allocator.alloc(
        u8,
        P.npk,
    ) catch return error.OutOfMemory;
    @memcpy(ek, &kp.pk);

    return .{
        .encryption_key = ek,
        .encrypted_path_secret = cts,
    };
}

/// Generate an UpdatePath for a sender. Per RFC 9420 Section 7.5.
///
/// 1. Derive path secrets from leaf_secret along the filtered
///    direct path.
/// 2. For each filtered path node, derive the node keypair and
///    encrypt the path secret to each member in the copath
///    resolution.
/// 3. Return the UpdatePath struct and the commit_secret.
///
/// `eph_seeds` is a flat array of [32]u8 seeds, one per HPKE
/// encryption in order (across all path nodes). The caller must
/// provide exactly enough seeds.
pub fn generateUpdatePath(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    sender: LeafIndex,
    new_leaf: LeafNode,
    group_context: []const u8,
    leaf_secret: *const [P.nh]u8,
    eph_seeds: []const [32]u8,
) !GeneratePathResult(P) {
    // 1. Get filtered direct path.
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);
    if (n_path == 0) return error.EmptyTree;

    // 2. Derive path secrets.
    var secrets: [max_path_nodes][P.nh]u8 = undefined;
    defer for (0..n_path) |i| {
        secureZero(&secrets[i]);
    };
    derivePathSecrets(P, leaf_secret, n_path, &secrets);

    // 3. Build UpdatePathNodes.
    const nodes = try buildUpdatePathNodes(
        P,
        allocator,
        tree,
        fdp.copath[0..n_path],
        &secrets,
        n_path,
        group_context,
        eph_seeds,
    );

    // 4. Derive commit_secret.
    const commit_secret = deriveCommitSecret(
        P,
        &secrets[n_path - 1],
    );

    return .{
        .update_path = .{
            .leaf_node = new_leaf,
            .nodes = nodes,
        },
        .commit_secret = commit_secret,
    };
}

/// Allocate and encrypt UpdatePathNodes for each copath entry.
fn buildUpdatePathNodes(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    copath: []const NodeIndex,
    secrets: *const [max_path_nodes][P.nh]u8,
    n_path: u32,
    group_context: []const u8,
    eph_seeds: []const [32]u8,
) ![]UpdatePathNode {
    var nodes = allocator.alloc(
        UpdatePathNode,
        n_path,
    ) catch return error.OutOfMemory;
    var node_count: u32 = 0;
    errdefer freeUpnSlice(allocator, nodes, node_count);

    var seed_idx: u32 = 0;
    for (0..n_path) |pi| {
        var res_buf: [RatchetTree.max_resolution_size]NodeIndex =
            undefined;
        const n_res: u32 = @intCast(
            (try tree.resolution(copath[pi], &res_buf)).len,
        );
        const seeds_end = seed_idx + n_res;
        if (seeds_end > eph_seeds.len)
            return error.MalformedUpdatePath;

        nodes[pi] = try encryptCommitPathNode(
            P,
            allocator,
            tree,
            &secrets[pi],
            copath[pi],
            group_context,
            eph_seeds[seed_idx..seeds_end],
        );
        node_count += 1;
        seed_idx += n_res;
    }
    return nodes;
}

/// Free a partially-initialized slice of UpdatePathNodes.
pub fn freeUpnSlice(
    allocator: std.mem.Allocator,
    nodes: []UpdatePathNode,
    count: u32,
) void {
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        nodes[i].deinit(allocator);
    }
    allocator.free(nodes);
}

/// Apply a received UpdatePath and recover the commit_secret.
///
/// Per RFC 9420 Section 7.5-7.6:
/// 1. Identify which copath node the receiver is under.
/// 2. Decrypt the corresponding encrypted_path_secret.
/// 3. Derive all subsequent path secrets up the tree.
/// 4. Verify that derived public keys match the UpdatePath nodes.
/// 5. Set the new keying material in the tree.
/// 6. Return the commit_secret.
pub fn applyUpdatePath(
    comptime P: type,
    tree: *RatchetTree,
    sender: LeafIndex,
    receiver: LeafIndex,
    update_path: *const UpdatePath,
    group_context: []const u8,
    receiver_sk: *const [P.nsk]u8,
    receiver_pk: *const [P.npk]u8,
) !ApplyPathResult(P) {
    // 1. Get filtered direct path.
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);
    if (n_path != update_path.nodes.len) {
        return error.MalformedUpdatePath;
    }

    // 2. Find receiver's position in the resolution.
    const pos = try findReceiverPos(
        tree,
        receiver,
        fdp.copath[0..n_path],
        &.{}, // No excluded leaves for applyUpdatePath.
    );

    // 3. Decrypt and derive path secrets.
    var secrets: [max_path_nodes][P.nh]u8 = undefined;
    const remaining = n_path - pos.node_idx;
    defer for (0..remaining) |i| {
        secureZero(&secrets[i]);
    };
    try decryptAndDerivePathSecrets(
        P,
        update_path,
        &pos,
        group_context,
        receiver_sk,
        receiver_pk,
        remaining,
        &secrets,
    );

    // 4. Verify and apply.
    try verifyAndApplyPath(
        P,
        tree,
        fdp.path[0..n_path],
        update_path,
        &secrets,
        pos.node_idx,
        remaining,
    );

    // 5. Set sender leaf.
    try tree.setLeaf(sender, update_path.leaf_node);

    // 6. Derive commit_secret from last path_secret.
    const commit_secret = deriveCommitSecret(
        P,
        &secrets[remaining - 1],
    );

    return .{ .commit_secret = commit_secret };
}

/// Decrypt the path secret at the receiver's position and derive
/// the remaining path secrets from it.
fn decryptAndDerivePathSecrets(
    comptime P: type,
    update_path: *const UpdatePath,
    pos: *const ReceiverPos,
    group_context: []const u8,
    receiver_sk: *const [P.nsk]u8,
    receiver_pk: *const [P.npk]u8,
    remaining: u32,
    secrets: *[max_path_nodes][P.nh]u8,
) !void {
    const ct = &update_path.nodes[pos.node_idx]
        .encrypted_path_secret[pos.ct_idx];
    var path_secret_0 = try decryptPathSecretFrom(
        P,
        ct,
        receiver_sk,
        receiver_pk,
        group_context,
    );
    defer secureZero(&path_secret_0);
    derivePathSecrets(P, &path_secret_0, remaining, secrets);
}

/// Decrypt the path secret from a received UpdatePath, verify
/// that derived public keys match the UpdatePath nodes, and
/// return the commit_secret.
///
/// Unlike applyUpdatePath, this function does NOT modify the
/// tree. The caller must merge public keys into the tree
/// beforehand (via applySenderPath) so that the tree hash used
/// in the provisional GroupContext is correct.
///
/// Per RFC 9420 Section 12.4.2 Step 8: the HPKE context must
/// use a provisional GroupContext with the new epoch and the
/// tree_hash computed after merging the UpdatePath.
pub fn decryptAndVerifyPath(
    comptime P: type,
    tree: *const RatchetTree,
    sender: LeafIndex,
    receiver: LeafIndex,
    update_path: *const UpdatePath,
    group_context: []const u8,
    receiver_sk: *const [P.nsk]u8,
    receiver_pk: *const [P.npk]u8,
) !ApplyPathResult(P) {
    // 1. Get filtered direct path.
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);
    if (n_path != update_path.nodes.len) {
        return error.MalformedUpdatePath;
    }

    // 2. Find receiver's position in the resolution.
    const pos = try findReceiverPos(
        tree,
        receiver,
        fdp.copath[0..n_path],
        &.{}, // No excluded leaves for decryptAndVerifyPath.
    );

    // 3. Decrypt path secret at that position.
    const ct = &update_path.nodes[pos.node_idx]
        .encrypted_path_secret[pos.ct_idx];
    var path_secret_0 = try decryptPathSecretFrom(
        P,
        ct,
        receiver_sk,
        receiver_pk,
        group_context,
    );
    defer secureZero(&path_secret_0);

    // 4. Derive remaining path secrets.
    const remaining = n_path - pos.node_idx;
    var secrets: [max_path_nodes][P.nh]u8 = undefined;
    defer for (0..remaining) |i| {
        secureZero(&secrets[i]);
    };
    derivePathSecrets(P, &path_secret_0, remaining, &secrets);

    // 5. Verify derived public keys match UpdatePath nodes.
    try verifyPathKeys(
        P,
        update_path,
        &secrets,
        pos.node_idx,
        remaining,
    );

    // 6. Derive commit_secret from last path_secret.
    const commit_secret = deriveCommitSecret(
        P,
        &secrets[remaining - 1],
    );

    return .{ .commit_secret = commit_secret };
}

/// Verify that derived public keys match UpdatePath nodes.
///
/// This is the verification-only portion of verifyAndApplyPath.
pub fn verifyPathKeys(
    comptime P: type,
    update_path: *const UpdatePath,
    secrets: *const [max_path_nodes][P.nh]u8,
    start_idx: u32,
    count: u32,
) (CryptoError || TreeError)!void {
    var si: u32 = 0;
    while (si < count) : (si += 1) {
        const pi = start_idx + si;
        var kp = try deriveNodeKeypair(P, &secrets[si]);
        defer secureZero(&kp.sk);

        const upn = &update_path.nodes[pi];
        if (upn.encryption_key.len != P.npk) {
            return error.MalformedUpdatePath;
        }
        if (!std.mem.eql(
            u8,
            upn.encryption_key[0..P.npk],
            &kp.pk,
        )) {
            return error.MalformedUpdatePath;
        }
    }
}

/// Apply an UpdatePath to the tree from the sender's perspective.
///
/// After generateUpdatePath produces the UpdatePath and
/// commit_secret, the sender must update their own copy of the
/// tree with the new parent node keys and new leaf node. Unlike
/// applyUpdatePath (for receivers), no HPKE decryption is
/// needed — the sender already has the public keys in the
/// UpdatePath.
pub fn applySenderPath(
    tree: *RatchetTree,
    sender: LeafIndex,
    update_path: *const UpdatePath,
) (TreeError || error{OutOfMemory})!void {
    // 1. Get filtered direct path.
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);
    if (n_path != update_path.nodes.len) {
        return error.MalformedUpdatePath;
    }

    // 2. Set parent nodes along the path.
    for (0..n_path) |pi| {
        const upn = &update_path.nodes[pi];
        try tree.setNode(
            fdp.path[pi],
            Node.initParent(.{
                .encryption_key = upn.encryption_key,
                .parent_hash = "",
                .unmerged_leaves = &.{},
            }),
        );
    }

    // 3. Set sender's new leaf.
    try tree.setLeaf(sender, update_path.leaf_node);
}

/// Merge derived public keys and a new leaf into the tree.
///
/// Like applySenderPath, but takes raw public key arrays instead
/// of an UpdatePath. Used during createCommit when the HPKE
/// ciphertexts have not yet been generated.
pub fn applySenderPathFromKeys(
    comptime npk: u32,
    tree: *RatchetTree,
    sender: LeafIndex,
    new_leaf: *const LeafNode,
    public_keys: []const [npk]u8,
) (TreeError || error{OutOfMemory})!void {
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);
    if (n_path != public_keys.len) {
        return error.MalformedUpdatePath;
    }

    for (0..n_path) |pi| {
        try tree.setNode(
            fdp.path[pi],
            Node.initParent(.{
                .encryption_key = &public_keys[pi],
                .parent_hash = "",
                .unmerged_leaves = &.{},
            }),
        );
    }

    try tree.setLeaf(sender, new_leaf.*);
}

/// Apply only parent-node public keys (no leaf) to the tree.
/// Used during createCommit to prepare the tree for parent_hash
/// computation before the leaf is signed.
pub fn applyParentKeysOnly(
    comptime npk: u32,
    tree: *RatchetTree,
    sender: LeafIndex,
    public_keys: []const [npk]u8,
) (TreeError || error{OutOfMemory})!void {
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);
    if (n_path != public_keys.len) {
        return error.MalformedUpdatePath;
    }
    for (0..n_path) |pi| {
        try tree.setNode(
            fdp.path[pi],
            Node.initParent(.{
                .encryption_key = &public_keys[pi],
                .parent_hash = "",
                .unmerged_leaves = &.{},
            }),
        );
    }
}

/// Compute the parent_hash for a leaf node. Returns the hash of
/// the leaf's immediate parent on the filtered direct path,
/// or null if the filtered direct path is empty (single leaf).
pub fn computeLeafParentHash(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    sender: LeafIndex,
) (TreeError || error{OutOfMemory})!?[P.nh]u8 {
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    if (fdp.path.len == 0) return null;
    // Leaf's parent_hash = parentHash(dp[0], osth(cp[0])).
    const pi = fdp.path[0].toUsize();
    const ul = if (pi < tree.nodes.len and
        tree.nodes[pi] != null and
        tree.nodes[pi].?.node_type == .parent)
        tree.nodes[pi].?.payload.parent.unmerged_leaves
    else
        &[_]LeafIndex{};
    const osth = try tree_hashes.originalSiblingTreeHash(
        P,
        allocator,
        tree,
        fdp.copath[0],
        ul,
    );
    return try tree_hashes.parentHash(P, tree, fdp.path[0], &osth);
}

/// Compute and set parent_hash values for nodes on the sender's
/// filtered direct path.
///
/// After merging an UpdatePath into the tree via applySenderPath
/// or applySenderPathFromKeys, the parent nodes have empty
/// parent_hash fields. This function computes the correct
/// parent_hash chain top-down per RFC 9420 Section 7.9.
///
/// The topmost path node's parent_hash is "" (it has no parent
/// on the path above it). For each subsequent node going down,
/// the parent_hash is computed from the parent node above.
///
/// The tree must own its contents (owns_contents = true) so that
/// parent_hash allocations are managed correctly.
pub fn setPathParentHashes(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *RatchetTree,
    sender: LeafIndex,
) (TreeError || error{OutOfMemory})!void {
    // 1. Get filtered direct path and copath.
    var p_buf: [max_path_nodes]NodeIndex = undefined;
    var c_buf: [max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_fp: u32 = @intCast(fdp.path.len);
    if (n_fp < 2) return;

    // 2. Compute sibling tree hashes for the filtered copath.
    // Per RFC 9420 Section 7.9: use originalSiblingTreeHash
    // which excludes unmerged_leaves of each path node.
    var sib_hashes: [max_path_nodes][P.nh]u8 = undefined;
    for (0..n_fp) |i| {
        const pi = fdp.path[i].toUsize();
        const ul = if (pi < tree.nodes.len and
            tree.nodes[pi] != null and
            tree.nodes[pi].?.node_type == .parent)
            tree.nodes[pi].?.payload.parent.unmerged_leaves
        else
            &[_]LeafIndex{};
        sib_hashes[i] = try tree_hashes.originalSiblingTreeHash(
            P,
            allocator,
            tree,
            fdp.copath[i],
            ul,
        );
    }

    // 3. Top-down: fp[n-1] has parent_hash = "" (already set).
    //    For i from n-2 down to 0:
    //      fp[i].parent_hash = parentHash(fp[i+1], sib[i+1])
    //    Loop bounded by n_fp <= max_path_nodes (at most 30).
    assert(n_fp <= max_path_nodes);
    try applyParentHashesTopDown(
        P,
        tree,
        fdp.path[0..n_fp],
        &sib_hashes,
        n_fp,
    );
}

/// Walk the filtered direct path top-down and assign parent
/// hashes to each node in the owned tree.
fn applyParentHashesTopDown(
    comptime P: type,
    tree: *RatchetTree,
    path: []const NodeIndex,
    sib_hashes: *const [max_path_nodes][P.nh]u8,
    n_fp: u32,
) (TreeError || error{OutOfMemory})!void {
    var i: u32 = n_fp - 2;
    while (true) {
        const parent_idx = path[i + 1];
        const ph = try tree_hashes.parentHash(
            P,
            tree,
            parent_idx,
            &sib_hashes[i + 1],
        );

        const ci = path[i].toUsize();
        const slot = &tree.nodes[ci];
        if (slot.*) |_| {
            const pn = &slot.*.?.payload.parent;
            if (tree.owns_contents) {
                const new_ph = try tree.allocator.alloc(
                    u8,
                    P.nh,
                );
                @memcpy(new_ph, &ph);
                if (pn.parent_hash.len > 0) {
                    tree.allocator.free(pn.parent_hash);
                }
                pn.parent_hash = new_ph;
            } else {
                return error.IndexOutOfRange;
            }
        }
        if (i == 0) break;
        i -= 1;
    }
}

/// Result of applying an UpdatePath.
pub fn ApplyPathResult(comptime P: type) type {
    return struct { commit_secret: [P.nh]u8 };
}

/// Position of the receiver in the UpdatePath ciphertext array.
pub const ReceiverPos = struct {
    /// Index into update_path.nodes.
    node_idx: u32,
    /// Index into that node's encrypted_path_secret.
    ct_idx: u32,
    /// The resolution node that matched the receiver.
    /// Used to determine which private key to use for decryption.
    res_node: NodeIndex,
};

/// Find which UpdatePathNode and ciphertext index corresponds to
/// the receiver.
///
/// `excluded_leaves` lists leaves added in the same commit. Per
/// RFC 9420 Section 12.4.2, the sender does NOT encrypt the path
/// to newly-added members (they receive path secrets via Welcome).
/// These leaves are skipped when computing ciphertext indices.
pub fn findReceiverPos(
    tree: *const RatchetTree,
    receiver: LeafIndex,
    copath: []const NodeIndex,
    excluded_leaves: []const LeafIndex,
) TreeError!ReceiverPos {
    var res_buf: [RatchetTree.max_resolution_size]NodeIndex =
        undefined;

    for (copath, 0..) |cp_node, pi| {
        const res = try tree.resolution(cp_node, &res_buf);
        // Track ciphertext index, skipping excluded leaves.
        var ct_idx: u32 = 0;
        for (res) |res_node| {
            if (isExcludedLeaf(res_node, excluded_leaves)) {
                continue;
            }
            // Check: is receiver under this resolution node?
            if (isReceiverNode(
                tree,
                receiver,
                res_node,
            )) {
                return .{
                    .node_idx = @intCast(pi),
                    .ct_idx = ct_idx,
                    .res_node = res_node,
                };
            }
            ct_idx += 1;
        }
    }
    return error.MalformedUpdatePath;
}

/// Check whether a resolution node is a leaf that should be
/// excluded (newly added in the same commit).
fn isExcludedLeaf(
    node_idx: NodeIndex,
    excluded: []const LeafIndex,
) bool {
    if (!tree_math.isLeaf(node_idx)) return false;
    for (excluded) |ex| {
        if (node_idx.toU32() == ex.toNodeIndex().toU32()) {
            return true;
        }
    }
    return false;
}

/// Copy resolution entries into `out`, skipping any leaf nodes
/// that appear in `excluded`. Returns the filtered slice.
fn filterResolution(
    res: []const NodeIndex,
    out: *[RatchetTree.max_resolution_size]NodeIndex,
    excluded: []const LeafIndex,
) []const NodeIndex {
    if (excluded.len == 0) return res;
    var count: u32 = 0;
    for (res) |node_idx| {
        if (!isExcludedLeaf(node_idx, excluded)) {
            out[count] = node_idx;
            count += 1;
        }
    }
    return out[0..count];
}

/// Check whether the receiver leaf is "under" the given resolution
/// node. A leaf resolution node matches by index equality. A parent
/// resolution node matches if the receiver is NOT in the parent's
/// unmerged_leaves list (meaning the receiver holds the parent's
/// private key from a prior epoch).
fn isReceiverNode(
    tree: *const RatchetTree,
    receiver: LeafIndex,
    res_node: NodeIndex,
) bool {
    // For leaf resolution nodes, just compare indices.
    if (tree_math.isLeaf(res_node)) {
        return res_node.toU32() == receiver.toNodeIndex().toU32();
    }
    // For parent resolution nodes: the receiver holds this
    // parent's private key unless they are listed in the
    // parent's unmerged_leaves (which means they joined after
    // the parent key was last set).
    const index = res_node.toUsize();
    if (index >= tree.nodes.len) return false;
    const node = tree.nodes[index] orelse return false;
    if (node.node_type != .parent) return false;
    // If receiver IS in unmerged_leaves, they do NOT hold the
    // parent key — they will match on their own leaf entry
    // elsewhere in the resolution.
    for (node.payload.parent.unmerged_leaves) |ul| {
        if (ul.toU32() == receiver.toU32()) return false;
    }
    // Receiver is a descendant who holds the parent key.
    return tree_math.isInSubtree(res_node, receiver);
}

/// Verify derived public keys match the UpdatePath and set parent
/// nodes in the tree.
fn verifyAndApplyPath(
    comptime P: type,
    tree: *RatchetTree,
    path: []const NodeIndex,
    update_path: *const UpdatePath,
    secrets: *const [max_path_nodes][P.nh]u8,
    start_idx: u32,
    count: u32,
) (CryptoError || TreeError || error{OutOfMemory})!void {
    var si: u32 = 0;
    while (si < count) : (si += 1) {
        const pi = start_idx + si;
        var kp = try deriveNodeKeypair(P, &secrets[si]);
        defer secureZero(&kp.sk);

        // Verify the public key matches.
        const upn = &update_path.nodes[pi];
        if (upn.encryption_key.len != P.npk) {
            return error.MalformedUpdatePath;
        }
        if (!std.mem.eql(
            u8,
            upn.encryption_key[0..P.npk],
            &kp.pk,
        )) {
            return error.MalformedUpdatePath;
        }

        // Set the parent node in the tree.
        try tree.setNode(
            path[pi],
            Node.initParent(.{
                .encryption_key = upn.encryption_key,
                .parent_hash = "",
                .unmerged_leaves = &.{},
            }),
        );
    }
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const Credential = @import(
    "../credential/credential.zig",
).Credential;

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

    const path = UpdatePath{
        .leaf_node = makeTestLeaf("dave"),
        .nodes = &nodes,
    };

    var buf: [1024]u8 = undefined;
    const end = try path.encode(&buf, 0);

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

const Default =
    @import("../crypto/default.zig")
        .DhKemX25519Sha256Aes128GcmEd25519;

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
