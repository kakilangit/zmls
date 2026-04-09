//! Tree hash and parent hash computation per RFC 9420
//! Sections 7.8-7.9. Verifies honest update paths.
// Tree hash and parent hash computation per RFC 9420 Sections 7.8-7.9.
//
// Tree hash: a recursive hash over the tree structure used in the
// GroupContext to bind the group to a specific tree state.
//
// Parent hash: links parent nodes along an update path to prove
// that the path was constructed honestly. Used to verify that a
// committer populated the tree correctly.
//
// Both computations are generic over the CryptoProvider type (comptime).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const primitives = @import("../crypto/primitives.zig");
const errors = @import("../common/errors.zig");
const tree_math = @import("math.zig");
const node_mod = @import("node.zig");
const ratchet_tree_mod = @import("ratchet_tree.zig");

const NodeIndex = types.NodeIndex;
const LeafIndex = types.LeafIndex;
const TreeError = errors.TreeError;
const EncodeError = codec.EncodeError;
const Node = node_mod.Node;
const LeafNode = node_mod.LeafNode;
const ParentNode = node_mod.ParentNode;
const NodeType = node_mod.NodeType;
const RatchetTree = ratchet_tree_mod.RatchetTree;

/// Maximum buffer size for encoding a TreeHashInput.
/// Must be large enough for the largest possible node encoding
/// plus the left/right hash fields.
const max_hash_input_buf: u32 = 8192;

/// Maximum tree depth (matches ratchet_tree.zig).
const max_depth: u32 = 32;

// -- Tree Hash (Section 7.8) ------------------------------------------------

/// Compute the tree hash of a node in the ratchet tree.
///
/// Per RFC 9420 Section 7.8:
///   TreeHash(node) = H(TreeHashInput)
///
/// where TreeHashInput encodes the node type, the node contents,
/// and (for parent nodes) the tree hashes of the left and right
/// children.
///
/// Uses an iterative post-order traversal instead of recursion
/// (per RULES.md: no recursion).
pub fn treeHash(
    comptime Crypto: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    root_idx: NodeIndex,
) (TreeError || error{OutOfMemory})![Crypto.nh]u8 {
    assert(tree.leaf_count > 0);
    // Post-order traversal using an explicit stack.
    // Each entry is a node index. We process children before parents.
    //
    // Strategy: push nodes onto a work stack. For each parent, we
    // need both children's hashes first. We store computed hashes
    // in a flat array indexed by NodeIndex.
    //
    // Since the tree width is bounded by leaf_count, we use the
    // allocator-free approach: compute hashes bottom-up by level.

    // We need to store hashes for all nodes in the subtree rooted
    // at root_idx. Use a bounded iterative approach.
    const width = tree.nodeCount();
    if (root_idx.toU32() >= width) return error.IndexOutOfRange;

    const hashes = allocator.alloc(
        [Crypto.nh]u8,
        width,
    ) catch return error.OutOfMemory;
    defer allocator.free(hashes);

    // Process nodes bottom-up by level. Level 0 = leaves, then
    // level 1, 2, etc. This guarantees children are hashed before
    // parents.
    const max_level = tree_math.level(
        tree_math.root(tree.leaf_count),
    );

    // Level 0: hash all leaves in the subtree.
    var lv: u32 = 0;
    while (lv <= max_level) : (lv += 1) {
        var idx: u32 = 0;
        while (idx < width) : (idx += 1) {
            const ni = NodeIndex.fromU32(idx);
            if (tree_math.level(ni) != lv) continue;

            // Check if this node is in the subtree of root_idx.
            if (!isInSubtree(ni, root_idx)) continue;

            if (lv == 0) {
                // Leaf node.
                hashes[idx] = try hashLeafNode(
                    Crypto,
                    tree,
                    ni,
                );
            } else {
                hashes[idx] = try hashParentInSubtree(
                    Crypto,
                    tree,
                    ni,
                    hashes,
                    width,
                );
            }
        }
    }

    return hashes[root_idx.toU32()];
}

/// Hash a parent node whose children have already been hashed.
/// Clamps the right child to tree width, treating out-of-range
/// children as blank leaves.
fn hashParentInSubtree(
    comptime Crypto: type,
    tree: *const RatchetTree,
    ni: NodeIndex,
    hashes: [][Crypto.nh]u8,
    width: u32,
) (TreeError || error{OutOfMemory})![Crypto.nh]u8 {
    const l = tree_math.left(ni);
    const r = tree_math.right(ni);
    const r_idx = r.toU32();
    const left_hash = &hashes[l.toU32()];
    var right_hash: [Crypto.nh]u8 = undefined;
    if (r_idx < width) {
        right_hash = hashes[r_idx];
    } else {
        right_hash = try hashBlankLeaf(
            Crypto,
            r_idx,
        );
    }
    return try hashParentNode(
        Crypto,
        tree,
        ni,
        left_hash,
        &right_hash,
    );
}

/// Compute tree hashes for ALL nodes in the tree.
/// Returns a heap-allocated array of `nh`-byte hashes, one per
/// NodeIndex (0..width-1).
pub fn allTreeHashes(
    comptime Crypto: type,
    tree: *const RatchetTree,
    allocator: std.mem.Allocator,
) (TreeError || error{OutOfMemory})![][Crypto.nh]u8 {
    const width = tree.nodeCount();
    const scratch = try allocator.alloc(
        [Crypto.nh]u8,
        width,
    );
    defer allocator.free(scratch);

    const root_idx = tree_math.root(tree.leaf_count);
    const max_level = tree_math.level(root_idx);

    var lv: u32 = 0;
    while (lv <= max_level) : (lv += 1) {
        var idx: u32 = 0;
        while (idx < width) : (idx += 1) {
            const ni = NodeIndex.fromU32(idx);
            if (tree_math.level(ni) != lv) continue;

            if (lv == 0) {
                scratch[idx] = try hashLeafNode(
                    Crypto,
                    tree,
                    ni,
                );
            } else {
                const l = tree_math.left(ni);
                const r = tree_math.right(ni);
                const r_idx = r.toU32();
                const left_hash = &scratch[l.toU32()];
                var right_hash: [Crypto.nh]u8 = undefined;
                if (r_idx < width) {
                    right_hash = scratch[r_idx];
                } else {
                    right_hash = try hashBlankLeaf(
                        Crypto,
                        r_idx,
                    );
                }
                scratch[idx] = try hashParentNode(
                    Crypto,
                    tree,
                    ni,
                    left_hash,
                    &right_hash,
                );
            }
        }
    }

    // Copy to heap-allocated result.
    const result = try allocator.alloc(
        [Crypto.nh]u8,
        width,
    );
    @memcpy(result, scratch);
    return result;
}

/// Check if `node` is in the subtree rooted at `root`.
fn isInSubtree(node: NodeIndex, sub_root: NodeIndex) bool {
    const n = node.toU32();
    const r = sub_root.toU32();
    const rl = tree_math.level(sub_root);
    // A node is in the subtree of root if, when both are shifted
    // right by (root_level + 1), they have the same value.
    if (rl >= 31) return true; // root_level covers everything
    const shift: u5 = @intCast(rl + 1);
    return (n >> shift) == (r >> shift) and
        n >= (r - ((@as(u32, 1) << @intCast(rl)) - 1)) and
        n <= (r + ((@as(u32, 1) << @intCast(rl)) - 1));
}

/// Hash a leaf node for tree hash computation.
///
/// LeafNodeHashInput:
///   uint32 leaf_index;
///   optional<LeafNode> leaf_node;
fn hashLeafNode(
    comptime Crypto: type,
    tree: *const RatchetTree,
    idx: NodeIndex,
) TreeError![Crypto.nh]u8 {
    var buf: [max_hash_input_buf]u8 = undefined;
    var pos: u32 = 0;

    // NodeType = leaf (1).
    pos = codec.encodeUint8(&buf, pos, @intFromEnum(
        NodeType.leaf,
    )) catch return error.IndexOutOfRange;

    // leaf_index (u32).
    const leaf_index: u32 = idx.toU32() / 2;
    pos = codec.encodeUint32(
        &buf,
        pos,
        leaf_index,
    ) catch return error.IndexOutOfRange;

    // optional<LeafNode>.
    const i = idx.toUsize();
    if (i < tree.nodes.len and tree.nodes[i] != null) {
        // Present: 1 byte + encoded LeafNode.
        pos = codec.encodeUint8(
            &buf,
            pos,
            1,
        ) catch return error.IndexOutOfRange;
        const leaf = &tree.nodes[i].?.payload.leaf;
        pos = leaf.encode(
            &buf,
            pos,
        ) catch return error.IndexOutOfRange;
    } else {
        // Absent: 0 byte.
        pos = codec.encodeUint8(
            &buf,
            pos,
            0,
        ) catch return error.IndexOutOfRange;
    }

    return Crypto.hash(buf[0..pos]);
}

/// Hash a blank leaf that is beyond the tree width.
fn hashBlankLeaf(
    comptime Crypto: type,
    node_idx: u32,
) TreeError![Crypto.nh]u8 {
    var buf: [16]u8 = undefined;
    var pos: u32 = 0;

    // NodeType = leaf (1).
    pos = codec.encodeUint8(
        &buf,
        pos,
        @intFromEnum(NodeType.leaf),
    ) catch return error.IndexOutOfRange;

    // leaf_index (u32).
    const leaf_index: u32 = node_idx / 2;
    pos = codec.encodeUint32(
        &buf,
        pos,
        leaf_index,
    ) catch return error.IndexOutOfRange;

    // optional<LeafNode> = absent.
    pos = codec.encodeUint8(
        &buf,
        pos,
        0,
    ) catch return error.IndexOutOfRange;

    return Crypto.hash(buf[0..pos]);
}

/// Hash a parent node for tree hash computation.
///
/// ParentNodeHashInput:
///   HPKEPublicKey encryption_key;
///   opaque parent_hash<V>;
///   uint32 unmerged_leaves<V>;
///   opaque left_hash<V>;
///   opaque right_hash<V>;
fn hashParentNode(
    comptime Crypto: type,
    tree: *const RatchetTree,
    idx: NodeIndex,
    left_hash: *const [Crypto.nh]u8,
    right_hash: *const [Crypto.nh]u8,
) TreeError![Crypto.nh]u8 {
    var buf: [max_hash_input_buf]u8 = undefined;
    var pos: u32 = 0;

    // NodeType = parent (2).
    pos = codec.encodeUint8(&buf, pos, @intFromEnum(
        NodeType.parent,
    )) catch return error.IndexOutOfRange;

    const i = idx.toUsize();
    if (i < tree.nodes.len and tree.nodes[i] != null) {
        // Present: 1 byte + encoded ParentNode.
        pos = codec.encodeUint8(
            &buf,
            pos,
            1,
        ) catch return error.IndexOutOfRange;
        const pn = &tree.nodes[i].?.payload.parent;
        // encryption_key<V>.
        pos = codec.encodeVarVector(
            &buf,
            pos,
            pn.encryption_key,
        ) catch return error.IndexOutOfRange;
        // parent_hash<V>.
        pos = codec.encodeVarVector(
            &buf,
            pos,
            pn.parent_hash,
        ) catch return error.IndexOutOfRange;
        // unmerged_leaves<V>.
        pos = encodeLeafIndexList(
            &buf,
            pos,
            pn.unmerged_leaves,
        ) catch return error.IndexOutOfRange;
    } else {
        // Absent: 0 byte.
        pos = codec.encodeUint8(
            &buf,
            pos,
            0,
        ) catch return error.IndexOutOfRange;
    }

    // left_hash<V>.
    pos = codec.encodeVarVector(
        &buf,
        pos,
        left_hash,
    ) catch return error.IndexOutOfRange;

    // right_hash<V>.
    pos = codec.encodeVarVector(
        &buf,
        pos,
        right_hash,
    ) catch return error.IndexOutOfRange;

    return Crypto.hash(buf[0..pos]);
}

// -- Parent Hash (Section 7.9) ----------------------------------------------

/// Compute the parent hash for a parent node.
///
/// Per RFC 9420 Section 7.9:
///   ParentHashInput:
///     HPKEPublicKey encryption_key;
///     opaque parent_hash<V>;
///     opaque original_sibling_tree_hash<V>;
///
///   parent_hash(node) = H(ParentHashInput)
///
/// The `encryption_key` and `parent_hash` are from the parent node itself.
/// The `original_sibling_tree_hash` is the tree hash of the sibling of
/// the child through which the path descends.
///
/// Parameters:
///   - parent_idx: the parent node whose parent_hash we compute.
///   - sibling_tree_hash: pre-computed tree hash of the sibling.
pub fn parentHash(
    comptime Crypto: type,
    tree: *const RatchetTree,
    parent_idx: NodeIndex,
    sibling_tree_hash: *const [Crypto.nh]u8,
) TreeError![Crypto.nh]u8 {
    assert(!tree_math.isLeaf(parent_idx));
    var buf: [max_hash_input_buf]u8 = undefined;
    var pos: u32 = 0;

    const i = parent_idx.toUsize();
    if (i >= tree.nodes.len) return error.IndexOutOfRange;

    if (tree.nodes[i]) |n| {
        if (n.node_type != .parent) return error.WrongNodeType;
        const pn = &n.payload.parent;
        // encryption_key<V>.
        pos = codec.encodeVarVector(
            &buf,
            pos,
            pn.encryption_key,
        ) catch return error.IndexOutOfRange;
        // parent_hash<V>.
        pos = codec.encodeVarVector(
            &buf,
            pos,
            pn.parent_hash,
        ) catch return error.IndexOutOfRange;
    } else {
        return error.BlankNode;
    }

    // original_sibling_tree_hash<V>.
    pos = codec.encodeVarVector(
        &buf,
        pos,
        sibling_tree_hash,
    ) catch return error.IndexOutOfRange;

    return Crypto.hash(buf[0..pos]);
}

/// Verify parent hashes for the entire tree.
///
/// Per RFC 9420 Section 7.9.2 (bottom-up approach):
///
/// 1. For each non-blank, commit-source leaf, build a parent-hash
///    chain upward through its filtered direct path. The chain
///    continues as long as each link is valid. It stops at the
///    first mismatch (which is normal when other members have
///    committed since the leaf's last update).
///
/// 2. Every non-blank parent node must be covered by exactly one
///    chain. Uncovered or doubly-covered nodes indicate an
///    invalid tree.
///
/// Returns error.ParentHashMismatch if the tree is invalid.
pub fn verifyParentHashes(
    comptime Crypto: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
) (TreeError || error{OutOfMemory})!void {
    const width = tree.nodeCount();
    const covered = allocator.alloc(
        bool,
        width,
    ) catch return error.OutOfMemory;
    defer allocator.free(covered);
    @memset(covered, false);

    // Count non-blank parent nodes.
    var nb_parents: u32 = 0;
    var idx: u32 = 0;
    while (idx < width) : (idx += 1) {
        if (idx & 1 == 0) continue; // leaf
        if (tree.nodes[idx] != null) nb_parents += 1;
    }

    // No non-blank parents: nothing to verify.
    if (nb_parents == 0) return;

    // For each non-blank, commit-source leaf, build a chain.
    var li: u32 = 0;
    while (li < tree.leaf_count) : (li += 1) {
        const leaf_ni_val = li * 2;
        if (leaf_ni_val >= width) continue;
        if (tree.nodes[leaf_ni_val] == null) continue;
        const leaf_node = &tree.nodes[leaf_ni_val].?
            .payload.leaf;
        if (leaf_node.source != .commit) continue;

        try buildChain(
            Crypto,
            allocator,
            tree,
            types.LeafIndex.fromU32(li),
            leaf_node,
            covered,
        );
    }

    // Verify every non-blank parent is covered.
    idx = 0;
    while (idx < width) : (idx += 1) {
        if (idx & 1 == 0) continue;
        if (tree.nodes[idx] != null and !covered[idx]) {
            return error.ParentHashMismatch;
        }
    }
}

/// Build a parent-hash chain from a single commit-source leaf
/// upward. Marks each successfully linked parent as covered.
///
/// Walks the direct path (not filtered). Blank intermediate
/// nodes are skipped (they correspond to nodes that were blank
/// at commit time or blanked by later removes). The chain
/// stops at the first non-blank node whose parent hash does not
/// match the expected value.
fn buildChain(
    comptime Crypto: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    leaf: types.LeafIndex,
    leaf_node: *const LeafNode,
    covered: []bool,
) (TreeError || error{OutOfMemory})!void {
    // Compute direct path and copath.
    var dp_buf: [max_depth]NodeIndex = undefined;
    const dp = tree_math.directPath(
        leaf.toNodeIndex(),
        tree.leaf_count,
        &dp_buf,
    );

    var cp_buf: [max_depth]NodeIndex = undefined;
    const cp = tree_math.copath(
        leaf.toNodeIndex(),
        tree.leaf_count,
        &cp_buf,
    );

    // dp and cp have the same length.
    // dp[i] is a parent, cp[i] is the sibling child (copath).

    // If the direct path is empty, leaf must be root.
    if (dp.len == 0) {
        if (leaf_node.parent_hash) |ph| {
            if (ph.len != 0)
                return error.ParentHashMismatch;
        }
        return;
    }

    var expected: []const u8 = leaf_node.parent_hash orelse
        return; // null parent_hash: no chain
    if (expected.len == 0) return; // empty: no chain

    var i: u32 = 0;
    while (i < dp.len) : (i += 1) {
        const p_idx = dp[i];
        const s_idx = cp[i]; // sibling (copath child)
        const p_usize = p_idx.toUsize();

        // Skip blank parent nodes.
        if (p_usize >= tree.nodes.len or
            tree.nodes[p_usize] == null)
        {
            continue;
        }

        const result = try verifyChainLink(
            Crypto,
            allocator,
            tree,
            p_idx,
            s_idx,
            expected,
        );
        if (!result.matched) break;

        covered[p_usize] = true;
        expected = result.next_expected;
        if (expected.len == 0) break;
    }
}

const ChainLinkResult = struct {
    matched: bool,
    next_expected: []const u8,
};

/// Verify a single link in the parent-hash chain: compute the
/// original sibling tree hash, derive the expected parent hash,
/// and compare against the expected value.
fn verifyChainLink(
    comptime Crypto: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    p_idx: NodeIndex,
    s_idx: NodeIndex,
    expected: []const u8,
) (TreeError || error{OutOfMemory})!ChainLinkResult {
    const pn = &tree.nodes[p_idx.toUsize()].?.payload.parent;

    const osth = try originalSiblingTreeHash(
        Crypto,
        allocator,
        tree,
        s_idx,
        pn.unmerged_leaves,
    );

    const computed = try parentHash(
        Crypto,
        tree,
        p_idx,
        &osth,
    );

    if (expected.len != Crypto.nh or
        !primitives.constantTimeEql(
            Crypto.nh,
            expected[0..Crypto.nh],
            &computed,
        ))
    {
        return .{ .matched = false, .next_expected = &.{} };
    }

    return .{ .matched = true, .next_expected = pn.parent_hash };
}

/// Verify parent hashes for a single leaf. This is used when
/// processing a Commit (Section 12.4.2): verify the committer's
/// newly computed parent_hash chains to the root.
///
/// For per-leaf verification (as opposed to full-tree), every
/// link in the chain MUST be valid and the last fdp node's
/// parent_hash MUST be empty.
pub fn verifyLeafParentHash(
    comptime Crypto: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    leaf: types.LeafIndex,
) TreeError!void {
    assert(tree.leaf_count > 0);
    const leaf_ni = leaf.toNodeIndex();
    const leaf_usize = leaf_ni.toUsize();
    if (leaf_usize >= tree.nodes.len)
        return error.IndexOutOfRange;
    if (tree.nodes[leaf_usize] == null)
        return error.BlankNode;
    const leaf_node = &tree.nodes[leaf_usize].?.payload.leaf;

    if (leaf_node.source != .commit) return;

    var path_buf: [max_depth]NodeIndex = undefined;
    var cp_buf: [max_depth]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        leaf,
        &path_buf,
        &cp_buf,
    );

    if (fdp.path.len == 0) {
        if (leaf_node.parent_hash) |ph| {
            if (ph.len != 0)
                return error.ParentHashMismatch;
        }
        return;
    }

    // Verify strict chain: every link must match.
    const expected: []const u8 = leaf_node.parent_hash orelse
        return error.ParentHashMismatch;

    try verifyStrictParentHashChain(
        Crypto,
        allocator,
        tree,
        fdp.path[0..fdp.path.len],
        fdp.copath[0..fdp.path.len],
        expected,
    );
}

/// Walk the filtered direct path verifying that every parent-hash
/// link matches. Returns error.ParentHashMismatch on any mismatch
/// or if the final link is non-empty.
fn verifyStrictParentHashChain(
    comptime Crypto: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    path: []const NodeIndex,
    copath: []const NodeIndex,
    initial_expected: []const u8,
) (TreeError || error{OutOfMemory})!void {
    var expected = initial_expected;
    var i: u32 = 0;
    while (i < path.len) : (i += 1) {
        const p_idx = path[i];
        const s_idx = copath[i];
        const p_usize = p_idx.toUsize();

        const pn = &tree.nodes[p_usize].?.payload.parent;
        const osth = try originalSiblingTreeHash(
            Crypto,
            allocator,
            tree,
            s_idx,
            pn.unmerged_leaves,
        );
        const computed = try parentHash(
            Crypto,
            tree,
            p_idx,
            &osth,
        );

        if (expected.len != Crypto.nh or
            !primitives.constantTimeEql(
                Crypto.nh,
                expected[0..Crypto.nh],
                &computed,
            ))
        {
            return error.ParentHashMismatch;
        }

        expected = pn.parent_hash;
    }

    if (expected.len != 0)
        return error.ParentHashMismatch;
}

/// Compute the original sibling tree hash for parent hash
/// verification. Per RFC 9420 Section 7.9:
///
/// "original_sibling_tree_hash is the tree hash of S in the
/// ratchet tree modified as follows: For each leaf L in
/// P.unmerged_leaves, blank L and remove it from the
/// unmerged_leaves sets of all parent nodes."
///
/// Rather than mutating the tree, this function computes the
/// tree hash with a virtual blanking overlay: leaves in the
/// exclusion set are treated as blank, and parent nodes have
/// their unmerged_leaves filtered to exclude those leaves.
pub fn originalSiblingTreeHash(
    comptime Crypto: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    root_idx: NodeIndex,
    excluded_leaves: []const LeafIndex,
) (TreeError || error{OutOfMemory})![Crypto.nh]u8 {
    // If no exclusions, use the regular tree hash.
    if (excluded_leaves.len == 0) {
        return treeHash(Crypto, allocator, tree, root_idx);
    }

    const width = tree.nodeCount();
    if (root_idx.toU32() >= width) return error.IndexOutOfRange;
    const hashes = allocator.alloc(
        [Crypto.nh]u8,
        width,
    ) catch return error.OutOfMemory;
    defer allocator.free(hashes);

    const max_level = tree_math.level(
        tree_math.root(tree.leaf_count),
    );

    var lv: u32 = 0;
    while (lv <= max_level) : (lv += 1) {
        var idx: u32 = 0;
        while (idx < width) : (idx += 1) {
            const ni = NodeIndex.fromU32(idx);
            if (tree_math.level(ni) != lv) continue;
            if (!isInSubtree(ni, root_idx)) continue;

            if (lv == 0) {
                // Check if this leaf is excluded.
                if (isExcludedLeaf(idx, excluded_leaves)) {
                    hashes[idx] = try hashBlankLeaf(
                        Crypto,
                        idx,
                    );
                } else {
                    hashes[idx] = try hashLeafNode(
                        Crypto,
                        tree,
                        ni,
                    );
                }
            } else {
                hashes[idx] = try hashFilteredParentInSubtree(
                    Crypto,
                    tree,
                    ni,
                    hashes,
                    width,
                    excluded_leaves,
                );
            }
        }
    }

    return hashes[root_idx.toU32()];
}

/// Hash a parent node in a filtered subtree, treating out-of-range
/// right children as blank leaves and applying exclusion filtering.
fn hashFilteredParentInSubtree(
    comptime Crypto: type,
    tree: *const RatchetTree,
    ni: NodeIndex,
    hashes: [][Crypto.nh]u8,
    width: u32,
    excluded_leaves: []const LeafIndex,
) (TreeError || error{OutOfMemory})![Crypto.nh]u8 {
    const l_child = tree_math.left(ni);
    const r_child = tree_math.right(ni);
    const r_val = r_child.toU32();
    const left_hash = &hashes[l_child.toU32()];
    var right_hash: [Crypto.nh]u8 = undefined;
    if (r_val < width) {
        right_hash = hashes[r_val];
    } else {
        right_hash = try hashBlankLeaf(
            Crypto,
            r_val,
        );
    }
    return try hashParentNodeFiltered(
        Crypto,
        tree,
        ni,
        left_hash,
        &right_hash,
        excluded_leaves,
    );
}

/// Check if a node index corresponds to an excluded leaf.
fn isExcludedLeaf(
    node_idx: u32,
    excluded: []const LeafIndex,
) bool {
    // Leaves have even node indices.
    if (node_idx & 1 != 0) return false;
    const leaf_idx: u32 = node_idx / 2;
    for (excluded) |ex| {
        if (ex.toU32() == leaf_idx) return true;
    }
    return false;
}

/// Hash a parent node for tree hash, filtering out excluded
/// leaves from unmerged_leaves.
fn hashParentNodeFiltered(
    comptime Crypto: type,
    tree: *const RatchetTree,
    idx: NodeIndex,
    left_hash: *const [Crypto.nh]u8,
    right_hash: *const [Crypto.nh]u8,
    excluded_leaves: []const LeafIndex,
) TreeError![Crypto.nh]u8 {
    var buf: [max_hash_input_buf]u8 = undefined;
    var pos: u32 = 0;

    // NodeType = parent (2).
    pos = codec.encodeUint8(&buf, pos, @intFromEnum(
        NodeType.parent,
    )) catch return error.IndexOutOfRange;

    const i = idx.toUsize();
    if (i < tree.nodes.len and tree.nodes[i] != null) {
        // Present: 1 byte + encoded ParentNode.
        pos = codec.encodeUint8(
            &buf,
            pos,
            1,
        ) catch return error.IndexOutOfRange;
        const pn = &tree.nodes[i].?.payload.parent;
        // encryption_key<V>.
        pos = codec.encodeVarVector(
            &buf,
            pos,
            pn.encryption_key,
        ) catch return error.IndexOutOfRange;
        // parent_hash<V>.
        pos = codec.encodeVarVector(
            &buf,
            pos,
            pn.parent_hash,
        ) catch return error.IndexOutOfRange;
        // unmerged_leaves<V> — filter out excluded leaves.
        pos = try encodeFilteredLeafIndexList(
            &buf,
            pos,
            pn.unmerged_leaves,
            excluded_leaves,
        );
    } else {
        // Absent: 0 byte.
        pos = codec.encodeUint8(
            &buf,
            pos,
            0,
        ) catch return error.IndexOutOfRange;
    }

    // left_hash<V>.
    pos = codec.encodeVarVector(
        &buf,
        pos,
        left_hash,
    ) catch return error.IndexOutOfRange;

    // right_hash<V>.
    pos = codec.encodeVarVector(
        &buf,
        pos,
        right_hash,
    ) catch return error.IndexOutOfRange;

    return Crypto.hash(buf[0..pos]);
}

/// Encode a leaf index list, excluding entries in the exclusion
/// set.
fn encodeFilteredLeafIndexList(
    buf: []u8,
    pos: u32,
    items: []const LeafIndex,
    excluded: []const LeafIndex,
) TreeError!u32 {
    // Count non-excluded items first.
    var count: u32 = 0;
    for (items) |item| {
        var skip = false;
        for (excluded) |ex| {
            if (ex.toU32() == item.toU32()) {
                skip = true;
                break;
            }
        }
        if (!skip) count += 1;
    }

    if (count > types.max_vec_length / 4)
        return error.IndexOutOfRange;
    const byte_len: u32 = count * 4;
    var p = varint.encode(buf, pos, byte_len) catch
        return error.IndexOutOfRange;
    for (items) |item| {
        var skip = false;
        for (excluded) |ex| {
            if (ex.toU32() == item.toU32()) {
                skip = true;
                break;
            }
        }
        if (!skip) {
            p = codec.encodeUint32(buf, p, item.toU32()) catch
                return error.IndexOutOfRange;
        }
    }
    return p;
}

// -- Helpers -----------------------------------------------------------------

fn encodeLeafIndexList(
    buf: []u8,
    pos: u32,
    items: []const LeafIndex,
) EncodeError!u32 {
    if (items.len > types.max_vec_length / 4)
        return error.BufferTooSmall;
    const byte_len: u32 = @intCast(items.len * 4);
    var p = try varint.encode(buf, pos, byte_len);
    for (items) |item| {
        p = try codec.encodeUint32(buf, p, item.toU32());
    }
    return p;
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const Credential = @import(
    "../credential/credential.zig",
).Credential;

const TestCrypto = @import("../crypto/default.zig")
    .DhKemX25519Sha256Aes128GcmEd25519;

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
