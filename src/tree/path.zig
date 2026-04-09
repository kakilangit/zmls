//! Tree mutation operations (addLeaf, removeLeaf), path generation,
//! path application, and parent hash computation per RFC 9420
//! Sections 7.4-7.5.
//!
//! Wire format types (HPKECiphertext, UpdatePathNode, UpdatePath)
//! are in update_path.zig. Path secret derivation and HPKE
//! encryption helpers are in path_secrets.zig.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const tree_math = @import("math.zig");
const node_mod = @import("node.zig");
const ratchet_tree_mod = @import("ratchet_tree.zig");
const update_path_mod = @import("update_path.zig");
const path_secrets_mod = @import("path_secrets.zig");

const primitives = @import("../crypto/primitives.zig");
const hpke_mod = @import("../crypto/hpke.zig");
const tree_hashes = @import("hashes.zig");

const NodeIndex = types.NodeIndex;
const LeafIndex = types.LeafIndex;
const TreeError = errors.TreeError;
const CryptoError = errors.CryptoError;
const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const Node = node_mod.Node;
const LeafNode = node_mod.LeafNode;
const ParentNode = node_mod.ParentNode;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const secureZero = primitives.secureZero;

// Re-export wire format types so existing importers continue
// to work via path_mod.HPKECiphertext, etc.
pub const HPKECiphertext = update_path_mod.HPKECiphertext;
pub const UpdatePathNode = update_path_mod.UpdatePathNode;
pub const UpdatePath = update_path_mod.UpdatePath;
pub const max_path_nodes = update_path_mod.max_path_nodes;
pub const max_ciphertexts = update_path_mod.max_ciphertexts;
pub const encodeHpkeCiphertextList =
    update_path_mod.encodeHpkeCiphertextList;
pub const decodeHpkeCiphertextList =
    update_path_mod.decodeHpkeCiphertextList;
pub const encodeUpdatePathNodeList =
    update_path_mod.encodeUpdatePathNodeList;
pub const decodeUpdatePathNodeList =
    update_path_mod.decodeUpdatePathNodeList;

// Re-export path secret functions.
pub const GeneratePathResult = path_secrets_mod.GeneratePathResult;
pub const derivePathSecrets = path_secrets_mod.derivePathSecrets;
pub const deriveCommitSecret = path_secrets_mod.deriveCommitSecret;
pub const NodeKeypair = path_secrets_mod.NodeKeypair;
pub const deriveNodeKeypair = path_secrets_mod.deriveNodeKeypair;
pub const encryptPathSecretTo =
    path_secrets_mod.encryptPathSecretTo;
pub const decryptPathSecretFrom =
    path_secrets_mod.decryptPathSecretFrom;
pub const encryptToResolution =
    path_secrets_mod.encryptToResolution;
pub const nodePublicKey = path_secrets_mod.nodePublicKey;
pub const freeCtSlice = path_secrets_mod.freeCtSlice;

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
            // If allocation fails, keep the old buffer AND
            // the old leaf_count to preserve the invariant
            // nodes.len == nodeWidth(leaf_count).
            return;
        };
        @memcpy(new_nodes, tree.nodes[0..new_width]);
        tree.allocator.free(tree.nodes);
        tree.nodes = new_nodes;
    }
    tree.leaf_count = new_leaf_count;
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
    eph_seeds: []const [P.seed_len]u8,
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
    eph_seeds: []const [P.seed_len]u8,
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
    eph_seeds: []const [P.seed_len]u8,
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
/// `eph_seeds` is a flat array of [P.seed_len]u8 seeds, one per HPKE
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
    eph_seeds: []const [P.seed_len]u8,
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
    eph_seeds: []const [P.seed_len]u8,
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
