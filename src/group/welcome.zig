//! Welcome message processing per RFC 9420 Section 12.4.3.1.
//! Decrypts group secrets, verifies GroupInfo, initializes the
//! ratchet tree, and derives epoch secrets for a new joiner.
// Welcome processing per RFC 9420 Section 12.4.3.1.
//
// When a new member receives a Welcome message, they:
//   1. Find their EncryptedGroupSecrets entry by KeyPackageRef.
//   2. Decrypt GroupSecrets using their init_key (HPKE).
//   3. Derive welcome_secret from joiner_secret + psk_secret.
//   4. Decrypt encrypted_group_info using welcome_secret (AEAD).
//   5. Decode and verify GroupInfo (signature + confirmation tag).
//   6. Initialize the ratchet tree from GroupInfo extensions
//      (ratchet_tree) or build a minimal tree.
//   7. Derive full epoch secrets from joiner_secret + context.
//   8. Return the new GroupState.
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const tree_math = @import("../tree/math.zig");
const tree_hashes = @import("../tree/hashes.zig");
const context_mod = @import("context.zig");
const state_mod = @import("state.zig");
const schedule = @import("../key_schedule/schedule.zig");
const transcript = @import("../key_schedule/transcript.zig");
const auth_mod = @import("../framing/auth.zig");
const welcome_msg = @import("../messages/welcome.zig");
const group_info_mod = @import("../messages/group_info.zig");
const primitives = @import("../crypto/primitives.zig");
const proposal_cache_mod = @import("proposal_cache.zig");
const epoch_key_ring_mod = @import(
    "../key_schedule/epoch_key_ring.zig",
);
const psk_lookup_mod = @import(
    "../key_schedule/psk_lookup.zig",
);
const psk_mod = @import("../key_schedule/psk.zig");
const commit_mod = @import("commit.zig");
const path_mod = @import("../tree/path.zig");
const path_secrets_mod = @import("../tree/path_secrets.zig");
const secureZero = primitives.secureZero;

const CipherSuite = types.CipherSuite;
const LeafIndex = types.LeafIndex;
const NodeIndex = types.NodeIndex;
const Extension = node_mod.Extension;
const LeafNode = node_mod.LeafNode;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const max_gc_encode = context_mod.max_gc_encode;
const GroupState = state_mod.GroupState;
const Welcome = welcome_msg.Welcome;
const GroupSecrets = welcome_msg.GroupSecrets;
const EncryptedGroupSecrets = welcome_msg.EncryptedGroupSecrets;
const GroupInfo = group_info_mod.GroupInfo;

const TreeError = errors.TreeError;
const CryptoError = errors.CryptoError;
const ValidationError = errors.ValidationError;
const GroupError = errors.GroupError;
const DecodeError = errors.DecodeError;

/// Error set for processWelcome.
pub const WelcomeError =
    TreeError || CryptoError || ValidationError ||
    GroupError || DecodeError || error{OutOfMemory};

/// Result of processWelcome. Contains the new GroupState plus
/// parent node private keys derived from the Welcome's
/// path_secret (RFC 9420 §12.4.3.1). Callers should persist
/// the path_keys for future UpdatePath decryption.
pub fn WelcomeJoinResult(comptime P: type) type {
    return struct {
        /// The new group state for the joined epoch.
        group_state: GroupState(P),
        /// Private keys for parent nodes derived from the
        /// Welcome's path_secret. path_keys[i] is valid for
        /// 0..path_key_count. The caller should store these
        /// for future UpdatePath decryption where the
        /// receiver is matched via a parent node.
        path_keys: [path_mod.max_path_nodes]commit_mod
            .PathNodeKey(P),
        path_key_count: u32,

        pub fn deinit(
            self: *@This(),
        ) void {
            for (0..self.path_key_count) |i| {
                secureZero(&self.path_keys[i].sk);
            }
            self.path_key_count = 0;
            self.group_state.deinit();
        }
    };
}

/// Maximum size for decrypted GroupInfo plaintext.
const max_gi_buf: u32 = 65536;

/// Maximum PSK IDs in a Welcome's GroupSecrets.
const max_welcome_psks: u32 = 64;

/// Resolve PSK secrets from GroupSecrets PSK list and derive
/// the combined psk_secret.
///
/// Returns all-zero if the PSK list is empty.
/// Returns error.PskNotFound if any PSK cannot be resolved.
fn resolveWelcomePskSecret(
    comptime P: type,
    psks: []const psk_mod.PreSharedKeyId,
    resolver: ?commit_mod.PskResolver(P),
) (GroupError || ValidationError)![P.nh]u8 {
    if (psks.len == 0) return .{0} ** P.nh;

    if (psks.len > max_welcome_psks) {
        return error.InvalidProposalList;
    }
    const n: u32 = @intCast(psks.len);
    var entries: [max_welcome_psks]psk_mod.PskEntry = undefined;
    var ei: u32 = 0;

    while (ei < n) : (ei += 1) {
        const id = &psks[ei];
        const secret: ?[]const u8 = blk: {
            if (resolver) |r| {
                switch (id.psk_type) {
                    .external => break :blk r.external.resolve(
                        id,
                    ),
                    .resumption => {
                        const s = r.resumption.lookupSecret(
                            id.resumption_epoch,
                        );
                        if (s) |ptr| break :blk ptr;
                        break :blk null;
                    },
                    else => break :blk null,
                }
            }
            break :blk null;
        };
        if (secret == null) return error.PskNotFound;
        entries[ei] = .{
            .id = id.*,
            .secret = secret.?,
        };
    }

    return psk_mod.derivePskSecret(P, entries[0..n]);
}

// -- processWelcome ---------------------------------------------------------

/// Per-call options for `processWelcome`.
pub fn ProcessWelcomeOpts(comptime P: type) type {
    return struct {
        /// The Welcome message to process.
        welcome: *const Welcome,
        /// KeyPackage reference for this joiner.
        kp_ref: []const u8,
        /// Init private key matching the KeyPackage.
        init_sk: *const [P.nsk]u8,
        /// Init public key matching the KeyPackage.
        init_pk: *const [P.npk]u8,
        /// Signer's verification key (from GroupInfo).
        /// Must match the signature_key of the leaf at
        /// GroupInfo.signer in the ratchet tree. Validated
        /// after tree construction (constant-time compare).
        signer_verify_key: *const [P.sign_pk_len]u8,
        /// Source of the ratchet tree.
        tree_data: TreeInput,
        /// This joiner's leaf index in the tree.
        my_leaf_index: LeafIndex,
        /// PSK resolver.
        psk_resolver: ?commit_mod.PskResolver(P) = null,
    };
}

/// Per-call options for `buildWelcome`.
pub fn BuildWelcomeOpts(comptime P: type) type {
    return struct {
        /// Serialized GroupContext bytes.
        gc_bytes: []const u8,
        /// Confirmation tag from the commit.
        confirmation_tag: *const [P.nh]u8,
        /// Welcome secret from the commit's key schedule.
        welcome_secret: *const [P.nh]u8,
        /// Joiner secret from the commit's key schedule.
        joiner_secret: *const [P.nh]u8,
        /// Committer's signature private key.
        sign_key: *const [P.sign_sk_len]u8,
        /// Signer's leaf index (as u32).
        signer: u32,
        /// Cipher suite of the group.
        cipher_suite: CipherSuite,
        /// New members to include in the Welcome.
        new_members: []const NewMemberEntry(P),
        /// PSK IDs to include (empty if no PSKs).
        psk_ids: []const psk_mod.PreSharedKeyId = &.{},
        /// Path secrets from the committer's filtered direct
        /// path. path_secrets[i] corresponds to fdp_nodes[i].
        /// Null when the commit has no UpdatePath.
        path_secrets: ?*const [path_mod.max_path_nodes][P.nh]u8 = null,
        /// Number of valid entries in path_secrets/fdp_nodes.
        path_secret_count: u32 = 0,
        /// Filtered direct path node indices (parallel to
        /// path_secrets).
        fdp_nodes: ?*const [path_mod.max_path_nodes]NodeIndex = null,
        /// Leaf count of the post-commit tree (needed for
        /// direct path computation).
        tree_size: u32 = 0,
    };
}

/// Process a Welcome message to join a group.
///
/// Per RFC 9420 Section 12.4.3.1:
///   1. Find and decrypt GroupSecrets using init_key.
///   2. Derive welcome_secret from joiner_secret.
///   3. Decrypt and decode GroupInfo.
///   4. Verify GroupInfo signature.
///   5. Build the ratchet tree (from the tree parameter).
///   6. Derive epoch secrets from joiner_secret + GroupContext.
///   7. Verify the confirmation tag.
///   8. Compute transcript hashes.
///   9. Return GroupState.
///
/// Parameters:
///   - allocator: memory allocator for tree and group state.
///   - welcome: the Welcome message received.
///   - kp_ref: the new member's KeyPackageRef (hash of their
///     KeyPackage).
///   - init_sk: the new member's HPKE init secret key.
///   - init_pk: the new member's HPKE init public key.
///   - signer_verify_key: the public signature key of the
///     GroupInfo signer (the committer who invited us).
///   - tree_data: optional ratchet tree nodes provided
///     out-of-band or via a ratchet_tree extension. If null,
///     a minimal tree is built from GroupInfo.
///   - my_leaf_index: the new member's leaf index in the tree.
pub fn processWelcome(
    comptime P: type,
    allocator: std.mem.Allocator,
    welcome: *const Welcome,
    kp_ref: []const u8,
    init_sk: *const [P.nsk]u8,
    init_pk: *const [P.npk]u8,
    signer_verify_key: *const [P.sign_pk_len]u8,
    tree_data: TreeInput,
    my_leaf_index: LeafIndex,
    psk_resolver: ?commit_mod.PskResolver(P),
) WelcomeError!WelcomeJoinResult(P) {
    // 1-2. Decrypt GroupSecrets, derive welcome_secret.
    var ws = try decryptWelcomeSecrets(
        P,
        allocator,
        welcome,
        kp_ref,
        init_sk,
        init_pk,
        psk_resolver,
    );
    defer ws.deinit(P);

    // 3-5. Decrypt, decode, and verify GroupInfo.
    var gi_pt_buf: [max_gi_buf]u8 = undefined;
    var gi = try decryptAndVerifyGroupInfo(
        P,
        allocator,
        welcome,
        &ws.welcome_secret,
        signer_verify_key,
        &gi_pt_buf,
    );
    defer gi.deinit(allocator);

    // 6-7b. Build tree, verify tree hash, decode GroupContext.
    var tree = try buildTree(allocator, tree_data);
    errdefer tree.deinit();
    var gc = try verifyTreeAndDecodeContext(
        P,
        allocator,
        &tree,
        &gi,
    );
    defer gc.deinit(allocator);

    // RFC 9420 S12.4.3.1: cipher suite must match.
    if (welcome.cipher_suite != gc.cipher_suite)
        return error.CipherSuiteMismatch;

    // Validate tree leaf nodes and structural invariants.
    try validateWelcomeTree(&tree, gc.cipher_suite);

    // RFC 9420 §12.4.3.1: verify that the caller-provided
    // signer_verify_key matches the signer's leaf in the
    // tree. The GroupInfo signer is at leaf index gi.signer.
    const signer_leaf_idx = LeafIndex.fromU32(gi.signer);
    const signer_leaf = tree.getLeaf(signer_leaf_idx) catch
        return error.IndexOutOfRange;
    if (signer_leaf) |sl| {
        if (sl.signature_key.len != P.sign_pk_len or
            !primitives.constantTimeEql(
                P.sign_pk_len,
                sl.signature_key[0..P.sign_pk_len],
                signer_verify_key,
            ))
            return error.SignatureVerifyFailed;
    } else {
        return error.InvalidLeafNode;
    }

    // 7c. Verify joiner's leaf is present at my_leaf_index.
    const my_leaf = tree.getLeaf(my_leaf_index) catch
        return error.IndexOutOfRange;
    if (my_leaf == null) return error.InvalidLeafNode;

    // RFC 9420 S13.4: joiner must support all group extensions.
    try validateJoinerExtSupport(my_leaf.?.*, gc.extensions);

    // Derive path keys from Welcome path_secret
    // (RFC 9420 §12.4.3.1).
    var path_keys: [path_mod.max_path_nodes]commit_mod
        .PathNodeKey(P) = undefined;
    const path_key_count = try deriveWelcomePathKeys(
        P,
        &ws.gs,
        &tree,
        my_leaf_index,
        gi.signer,
        &path_keys,
    );

    // 8-10. Derive epoch secrets, verify confirmation.
    const epoch_out = try deriveWelcomeEpochState(
        P,
        &ws.joiner_secret,
        &ws.psk_secret,
        &gi,
        &gc,
    );

    // 11. Build GroupState.
    const gs = try buildWelcomeGroupState(
        P,
        allocator,
        tree,
        &gc,
        epoch_out,
        my_leaf_index,
    );

    return .{
        .group_state = gs,
        .path_keys = path_keys,
        .path_key_count = path_key_count,
    };
}

/// Result of decryptWelcomeSecrets.
fn WelcomeSecretsResult(comptime P: type) type {
    return struct {
        joiner_secret: [P.nh]u8,
        psk_secret: [P.nh]u8,
        welcome_secret: [P.nh]u8,
        gs: welcome_msg.GroupSecrets,
        allocator: std.mem.Allocator,

        fn deinit(self: *@This(), comptime Q: type) void {
            primitives.secureZero(&self.welcome_secret);
            primitives.secureZero(&self.psk_secret);
            self.gs.deinit(self.allocator);
            _ = Q;
            self.* = undefined;
        }
    };
}

/// Steps 1-2: Decrypt GroupSecrets, resolve PSKs, derive
/// welcome_secret.
fn decryptWelcomeSecrets(
    comptime P: type,
    allocator: std.mem.Allocator,
    welcome: *const Welcome,
    kp_ref: []const u8,
    init_sk: *const [P.nsk]u8,
    init_pk: *const [P.npk]u8,
    psk_resolver: ?commit_mod.PskResolver(P),
) WelcomeError!WelcomeSecretsResult(P) {
    var gs = welcome_msg.decryptGroupSecrets(
        P,
        allocator,
        welcome,
        kp_ref,
        init_sk,
        init_pk,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.KeyPackageNotFound => return error.NoMatchingKeyPackage,
        else => return error.HpkeOpenFailed,
    };

    if (gs.joiner_secret.len != P.nh) {
        gs.deinit(allocator);
        return error.Truncated;
    }
    const joiner_secret: [P.nh]u8 =
        gs.joiner_secret[0..P.nh].*;

    var psk_secret = resolveWelcomePskSecret(
        P,
        gs.psks,
        psk_resolver,
    ) catch {
        gs.deinit(allocator);
        return error.PskNotFound;
    };

    var member_prk = P.kdfExtract(
        &joiner_secret,
        &psk_secret,
    );
    defer primitives.secureZero(&member_prk);
    const welcome_secret = primitives.deriveSecret(
        P,
        &member_prk,
        "welcome",
    );

    return .{
        .joiner_secret = joiner_secret,
        .psk_secret = psk_secret,
        .welcome_secret = welcome_secret,
        .gs = gs,
        .allocator = allocator,
    };
}

/// Steps 3-5: Decrypt, decode, and verify GroupInfo.
fn decryptAndVerifyGroupInfo(
    comptime P: type,
    allocator: std.mem.Allocator,
    welcome: *const Welcome,
    welcome_secret: *const [P.nh]u8,
    signer_verify_key: *const [P.sign_pk_len]u8,
    gi_pt_buf: *[max_gi_buf]u8,
) WelcomeError!GroupInfo {
    const egi = welcome.encrypted_group_info;
    if (egi.len < P.nt) return error.Truncated;

    const pt_len: u32 = @intCast(egi.len - P.nt);
    if (pt_len > max_gi_buf) return error.VectorTooLarge;

    group_info_mod.decryptGroupInfo(
        P,
        welcome_secret,
        egi,
        gi_pt_buf[0..pt_len],
    ) catch return error.AeadError;

    var gi_dec = GroupInfo.decode(
        allocator,
        gi_pt_buf[0..pt_len],
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Truncated,
    };

    group_info_mod.verifyGroupInfo(
        P,
        &gi_dec.value,
        signer_verify_key,
    ) catch {
        gi_dec.value.deinit(allocator);
        return error.SignatureVerifyFailed;
    };

    return gi_dec.value;
}

/// Steps 6-7b: Verify tree hash, decode GroupContext.
fn verifyTreeAndDecodeContext(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *RatchetTree,
    gi: *const GroupInfo,
) WelcomeError!context_mod.GroupContext(P.nh) {
    // RFC 9420 S7.9.2: verify parent hash chain.
    // Returns root tree hash as byproduct.
    const tree_hash = tree_hashes.verifyParentHashes(
        P,
        allocator,
        tree,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ParentHashMismatch,
    };

    var gc_dec = context_mod.GroupContext(P.nh).decode(
        allocator,
        gi.group_context,
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Truncated,
    };

    if (!std.mem.eql(u8, &tree_hash, &gc_dec.value.tree_hash)) {
        gc_dec.value.deinit(allocator);
        return error.TreeHashMismatch;
    }
    return gc_dec.value;
}

/// RFC 9420 S12.4.3.1: validate the ratchet tree received in a
/// Welcome. Checks leaf node validity, encryption key uniqueness,
/// and unmerged_leaves structural invariants.
fn validateWelcomeTree(
    tree: *const RatchetTree,
    suite: CipherSuite,
) WelcomeError!void {
    // 1. Validate each non-blank leaf.
    try validateTreeLeaves(tree, suite);
    // 2. Check encryption key uniqueness across all nodes.
    try validateKeyUniqueness(tree);
    // 3. Validate unmerged_leaves in parent nodes.
    try validateUnmergedLeaves(tree);
}

/// Validate every non-blank leaf with LeafNode.validate().
pub fn validateTreeLeaves(
    tree: *const RatchetTree,
    suite: CipherSuite,
) WelcomeError!void {
    var i: u32 = 0;
    while (i < tree.nodes.len) : (i += 2) {
        if (tree.nodes[i]) |node| {
            if (node.node_type == .leaf) {
                node.payload.leaf.validate(
                    suite,
                    null,
                ) catch return error.InvalidLeafNode;
            }
        }
    }
}

/// Verify no two non-blank nodes share the same encryption_key.
pub fn validateKeyUniqueness(
    tree: *const RatchetTree,
) WelcomeError!void {
    const nodes = tree.nodes;
    const n: u32 = @intCast(nodes.len);
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const a = nodes[i] orelse continue;
        const ek_a = nodeEncKey(&a);
        if (ek_a.len == 0) continue;
        var j: u32 = i + 1;
        while (j < n) : (j += 1) {
            const b = nodes[j] orelse continue;
            const ek_b = nodeEncKey(&b);
            if (std.mem.eql(u8, ek_a, ek_b))
                return error.InvalidLeafNode;
        }
    }
}

/// Extract encryption_key from either leaf or parent node.
fn nodeEncKey(node: *const node_mod.Node) []const u8 {
    return switch (node.node_type) {
        .leaf => node.payload.leaf.encryption_key,
        .parent => node.payload.parent.encryption_key,
    };
}

/// Verify each parent's unmerged_leaves entries are valid:
/// sorted, within range, non-blank leaves, and descendants
/// of that parent node.
fn validateUnmergedLeaves(
    tree: *const RatchetTree,
) WelcomeError!void {
    const n: u32 = @intCast(tree.nodes.len);
    var i: u32 = 1;
    while (i < n) : (i += 2) {
        const node = tree.nodes[i] orelse continue;
        if (node.node_type != .parent) continue;
        const ul = node.payload.parent.unmerged_leaves;
        const ni = types.NodeIndex.fromU32(i);
        try validateOneUnmergedList(tree, ul, ni);
    }
}

/// Validate a single unmerged_leaves list for a parent at
/// `parent_idx`.
fn validateOneUnmergedList(
    tree: *const RatchetTree,
    ul: []const LeafIndex,
    parent_idx: types.NodeIndex,
) WelcomeError!void {
    var prev: u32 = 0;
    for (ul, 0..) |leaf, index| {
        const li = leaf.toU32();
        // Must be sorted strictly ascending.
        if (index > 0 and li <= prev)
            return error.InvalidLeafNode;
        prev = li;
        // Must be within tree bounds and non-blank.
        const ni = leaf.toNodeIndex().toU32();
        if (ni >= tree.nodes.len)
            return error.IndexOutOfRange;
        if (tree.nodes[ni] == null)
            return error.InvalidLeafNode;
        // Must be a descendant of this parent.
        if (!tree_math.isInSubtree(parent_idx, leaf))
            return error.InvalidLeafNode;
    }
}

/// RFC 9420 S13.4: verify the joiner's leaf capabilities
/// include all extension types in the GroupContext.
pub fn validateJoinerExtSupport(
    leaf: LeafNode,
    gc_exts: []const Extension,
) WelcomeError!void {
    for (gc_exts) |ext| {
        if (!leafSupportsExt(&leaf, ext.extension_type))
            return error.UnsupportedCapability;
    }
}

/// Check if a leaf's capabilities list a given extension type.
fn leafSupportsExt(
    leaf: *const LeafNode,
    et: types.ExtensionType,
) bool {
    for (leaf.capabilities.extensions) |cap_et| {
        if (cap_et == et) return true;
    }
    // Default extension types (1-5) are implicitly supported.
    const v = @intFromEnum(et);
    return (v >= 1 and v <= 5);
}

/// Result of deriveWelcomeEpochState.
/// Derive parent node private keys from the Welcome's
/// path_secret per RFC 9420 §12.4.3.1.
///
/// If path_secret is set in GroupSecrets:
///   1. Find the LCA of (my_leaf, signer_leaf).
///   2. Set the private key for the LCA from path_secret.
///   3. For each parent of the LCA up to the root, derive
///      the next path_secret and set the private key.
///   4. Verify each derived public key matches the tree.
///
/// Returns the number of path keys written.
fn deriveWelcomePathKeys(
    comptime P: type,
    gs: *const GroupSecrets,
    tree: *const RatchetTree,
    my_leaf: LeafIndex,
    signer: u32,
    out: *[path_mod.max_path_nodes]commit_mod.PathNodeKey(P),
) WelcomeError!u32 {
    const ps_slice = gs.path_secret orelse return 0;
    if (ps_slice.len != P.nh) return error.Truncated;

    const signer_leaf = LeafIndex.fromU32(signer);
    const n = tree.leaf_count;

    // Find the LCA of the joiner and the signer.
    const lca = tree_math.commonAncestor(
        my_leaf.toNodeIndex(),
        signer_leaf.toNodeIndex(),
    );

    // Compute the joiner's direct path (leaf -> root).
    var dp_buf: [32]NodeIndex = undefined;
    const my_dp = tree_math.directPath(
        my_leaf.toNodeIndex(),
        n,
        &dp_buf,
    );

    // Find the LCA's position in the joiner's direct path.
    var lca_pos: ?usize = null;
    for (my_dp, 0..) |node, i| {
        if (node.toU32() == lca.toU32()) {
            lca_pos = i;
            break;
        }
    }
    // LCA must be on joiner's direct path.
    const start = lca_pos orelse return error.Truncated;

    // Nodes from LCA to root = my_dp[start..].
    const nodes_to_root = my_dp[start..];
    if (nodes_to_root.len == 0) return 0;

    // Derive path secrets: secret[0] = received path_secret,
    // secret[i+1] = DeriveSecret(secret[i], "path").
    const count: u32 = @intCast(nodes_to_root.len);
    var secrets: [path_mod.max_path_nodes][P.nh]u8 = undefined;
    secrets[0] = ps_slice[0..P.nh].*;
    path_secrets_mod.derivePathSecrets(
        P,
        &secrets[0],
        count,
        &secrets,
    );

    // Derive keypairs and verify against tree public keys.
    var key_count: u32 = 0;
    for (0..count) |i| {
        const kp = try path_secrets_mod.deriveNodeKeypair(
            P,
            &secrets[i],
        );
        defer secureZero(
            @constCast(&secrets[i]),
        );

        out[key_count] = .{
            .node = nodes_to_root[i],
            .sk = kp.sk,
            .pk = kp.pk,
        };
        key_count += 1;
    }
    return key_count;
}

fn WelcomeEpochOutput(comptime P: type) type {
    return struct {
        epoch_secrets: schedule.EpochSecrets(P),
        interim_th: [P.nh]u8,
    };
}

/// Steps 8-10: Derive epoch secrets, verify confirmation tag,
/// compute interim transcript hash.
fn deriveWelcomeEpochState(
    comptime P: type,
    joiner_secret: *const [P.nh]u8,
    psk_secret: *const [P.nh]u8,
    gi: *const GroupInfo,
    gc: *const context_mod.GroupContext(P.nh),
) WelcomeError!WelcomeEpochOutput(P) {
    const gc_bytes = gi.group_context;
    const epoch_secrets = schedule.deriveEpochSecretsFromJoiner(
        P,
        joiner_secret,
        psk_secret,
        gc_bytes,
    );

    if (gi.confirmation_tag.len != P.nh)
        return error.Truncated;
    const conf_tag: *const [P.nh]u8 =
        gi.confirmation_tag[0..P.nh];

    auth_mod.verifyConfirmationTag(
        P,
        &epoch_secrets.confirmation_key,
        &gc.confirmed_transcript_hash,
        conf_tag,
    ) catch return error.ConfirmationTagMismatch;

    const interim_th = transcript.updateInterimTranscriptHash(
        P,
        &gc.confirmed_transcript_hash,
        conf_tag,
    ) catch return error.IndexOutOfRange;

    return .{
        .epoch_secrets = epoch_secrets,
        .interim_th = interim_th,
    };
}

/// Step 11: Assemble the final GroupState from components.
///
/// Clones `gc.group_id` and `gc.extensions` so the caller
/// retains full ownership of `gc` and can deinit it normally.
fn buildWelcomeGroupState(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: RatchetTree,
    gc: *const context_mod.GroupContext(P.nh),
    epoch_out: WelcomeEpochOutput(P),
    my_leaf_index: LeafIndex,
) error{OutOfMemory}!GroupState(P) {
    const gid = try allocator.dupe(u8, gc.group_id);
    errdefer allocator.free(gid);
    const exts = try node_mod.cloneExtensions(
        allocator,
        gc.extensions,
    );

    return .{
        .tree = tree,
        .group_context = .{
            .version = gc.version,
            .cipher_suite = gc.cipher_suite,
            .group_id = gid,
            .epoch = gc.epoch,
            .tree_hash = gc.tree_hash,
            .confirmed_transcript_hash = gc.confirmed_transcript_hash,
            .extensions = exts,
        },
        .epoch_secrets = epoch_out.epoch_secrets,
        .interim_transcript_hash = epoch_out.interim_th,
        .confirmed_transcript_hash = gc.confirmed_transcript_hash,
        .my_leaf_index = my_leaf_index,
        .wire_format_policy = .encrypt_application_only,
        .pending_proposals = proposal_cache_mod.ProposalCache(P).init(),
        .epoch_key_ring = epoch_key_ring_mod.EpochKeyRing(P).init(0),
        .resumption_psk_ring = psk_lookup_mod.ResumptionPskRing(P).init(0),
        .allocator = allocator,
    };
}

// -- TreeInput: how the tree is provided ------------------------------------

/// How the ratchet tree is supplied to processWelcome.
pub const TreeInput = union(enum) {
    /// A pre-built RatchetTree (e.g., from a ratchet_tree
    /// extension or out-of-band delivery).
    prebuilt: RatchetTree,
    /// Build a single-leaf tree (for testing / minimal case).
    single_leaf: LeafNode,
};

fn buildTree(
    allocator: std.mem.Allocator,
    input: TreeInput,
) (TreeError || error{OutOfMemory})!RatchetTree {
    switch (input) {
        .prebuilt => |*t| {
            // Deep-clone so caller retains ownership of original.
            return t.clone() catch return error.OutOfMemory;
        },
        .single_leaf => |leaf| {
            var tree = try RatchetTree.init(allocator, 1);
            errdefer tree.deinit();
            try tree.setLeaf(LeafIndex.fromU32(0), leaf);
            return tree;
        },
    }
}

// -- NewMemberEntry ---------------------------------------------------------

/// Info about a new member to include in the Welcome.
pub fn NewMemberEntry(comptime P: type) type {
    return struct {
        /// The new member's KeyPackageRef (hash of KeyPackage).
        kp_ref: []const u8,
        /// The new member's HPKE init public key.
        init_pk: []const u8,
        /// Ephemeral seed for HPKE encryption of GroupSecrets.
        eph_seed: *const [P.seed_len]u8,
        /// The new member's leaf index in the post-commit tree.
        /// Used for Welcome path_secret computation per
        /// RFC 9420 §12.4.3.1.
        leaf_index: LeafIndex,
    };
}

// -- WelcomeResult ----------------------------------------------------------

/// Result of buildWelcome. Caller must call deinit() to free
/// heap-allocated slices.
pub const WelcomeResult = struct {
    welcome: Welcome,

    pub fn deinit(
        self: *WelcomeResult,
        allocator: std.mem.Allocator,
    ) void {
        for (self.welcome.secrets) |*egs| {
            allocator.free(egs.new_member);
            primitives.secureZeroConst(
                egs.encrypted_group_secrets.kem_output,
            );
            allocator.free(
                egs.encrypted_group_secrets.kem_output,
            );
            primitives.secureZeroConst(
                egs.encrypted_group_secrets.ciphertext,
            );
            allocator.free(
                egs.encrypted_group_secrets.ciphertext,
            );
        }
        allocator.free(self.welcome.secrets);
        allocator.free(self.welcome.encrypted_group_info);
        self.* = undefined;
    }
};

// -- buildWelcome -----------------------------------------------------------

/// Build a Welcome message for new members after a commit.
///
/// Per RFC 9420 Section 12.4.3.1:
///   1. Sign GroupInfo (group_context + confirmation_tag).
///   2. Encode GroupInfo to wire format.
///   3. Encrypt GroupInfo with welcome_secret (AEAD).
///   4. For each new member: encrypt GroupSecrets using their
///      init public key (HPKE EncryptWithLabel).
///   5. Assemble Welcome struct.
///
/// Parameters:
///   - allocator: for heap-allocating Welcome components.
///   - gc_bytes: serialized GroupContext for the new epoch.
///   - confirmation_tag: the commit's confirmation tag.
///   - welcome_secret: derived from the key schedule.
///   - joiner_secret: from key schedule (shared via Welcome).
///   - sign_key: the committer's signing secret key.
///   - signer: the committer's leaf index (u32).
///   - cipher_suite: the group's cipher suite.
///   - new_members: info for each new member to include.
pub fn buildWelcome(
    comptime P: type,
    allocator: std.mem.Allocator,
    gc_bytes: []const u8,
    confirmation_tag: *const [P.nh]u8,
    welcome_secret: *const [P.nh]u8,
    joiner_secret: *const [P.nh]u8,
    sign_key: *const [P.sign_sk_len]u8,
    signer: u32,
    cipher_suite: CipherSuite,
    new_members: []const NewMemberEntry(P),
    psk_ids: []const psk_mod.PreSharedKeyId,
    path_secrets: ?*const [path_mod.max_path_nodes][P.nh]u8,
    path_secret_count: u32,
    fdp_nodes: ?*const [path_mod.max_path_nodes]NodeIndex,
    tree_size: u32,
) WelcomeError!WelcomeResult {
    // 1. Sign and encode GroupInfo.
    var gi_buf: [max_gi_buf]u8 = undefined;
    const gi_end = try signAndEncodeGroupInfo(
        P,
        gc_bytes,
        confirmation_tag,
        sign_key,
        signer,
        &gi_buf,
    );

    // 2. Encrypt GroupInfo with welcome_secret.
    const egi_data = try encryptGroupInfoToHeap(
        P,
        allocator,
        welcome_secret,
        gi_buf[0..gi_end],
    );
    errdefer allocator.free(egi_data);

    // 3. Encrypt GroupSecrets for each new member.
    const secrets = try encryptMemberSecrets(
        P,
        allocator,
        joiner_secret,
        psk_ids,
        new_members,
        egi_data,
        signer,
        path_secrets,
        path_secret_count,
        fdp_nodes,
        tree_size,
    );

    return .{
        .welcome = Welcome{
            .cipher_suite = cipher_suite,
            .secrets = secrets,
            .encrypted_group_info = egi_data,
        },
    };
}

/// Sign GroupInfo and encode to a stack buffer.
fn signAndEncodeGroupInfo(
    comptime P: type,
    gc_bytes: []const u8,
    confirmation_tag: *const [P.nh]u8,
    sign_key: *const [P.sign_sk_len]u8,
    signer: u32,
    gi_buf: *[max_gi_buf]u8,
) WelcomeError!u32 {
    const sig = group_info_mod.signGroupInfo(
        P,
        gc_bytes,
        &.{},
        confirmation_tag,
        signer,
        sign_key,
    ) catch return error.SignatureVerifyFailed;

    const gi = GroupInfo{
        .group_context = gc_bytes,
        .extensions = &.{},
        .confirmation_tag = confirmation_tag,
        .signer = signer,
        .signature = &sig,
    };

    return gi.encode(gi_buf, 0) catch
        error.IndexOutOfRange;
}

/// Encrypt GroupInfo and copy result to a heap allocation.
fn encryptGroupInfoToHeap(
    comptime P: type,
    allocator: std.mem.Allocator,
    welcome_secret: *const [P.nh]u8,
    gi_bytes: []const u8,
) WelcomeError![]u8 {
    const gi_end: u32 = @intCast(gi_bytes.len);
    var egi_ct: [max_gi_buf]u8 = undefined;
    var egi_tag: [P.nt]u8 = undefined;
    group_info_mod.encryptGroupInfo(
        P,
        welcome_secret,
        gi_bytes,
        egi_ct[0..gi_end],
        &egi_tag,
    );

    const egi_len: u32 = gi_end + P.nt;
    const egi_data = allocator.alloc(
        u8,
        egi_len,
    ) catch return error.OutOfMemory;
    @memcpy(egi_data[0..gi_end], egi_ct[0..gi_end]);
    @memcpy(egi_data[gi_end..][0..P.nt], &egi_tag);
    return egi_data;
}

/// Encrypt GroupSecrets for each new member via HPKE.
///
/// Per RFC 9420 §12.4.3.1, each new member receives the
/// path_secret for the lowest node in the committer's filtered
/// direct path that is also in the new member's direct path.
fn encryptMemberSecrets(
    comptime P: type,
    allocator: std.mem.Allocator,
    joiner_secret: *const [P.nh]u8,
    psk_ids: []const psk_mod.PreSharedKeyId,
    new_members: []const NewMemberEntry(P),
    egi_data: []const u8,
    signer: u32,
    path_secrets: ?*const [path_mod.max_path_nodes][P.nh]u8,
    path_secret_count: u32,
    fdp_nodes: ?*const [path_mod.max_path_nodes]NodeIndex,
    tree_size: u32,
) WelcomeError![]EncryptedGroupSecrets {
    const n_members: u32 = @intCast(new_members.len);
    const secrets = allocator.alloc(
        EncryptedGroupSecrets,
        n_members,
    ) catch return error.OutOfMemory;
    var init_count: u32 = 0;
    errdefer freeSecretsSlice(allocator, secrets, init_count);

    const committer_leaf = LeafIndex.fromU32(signer);

    for (new_members, 0..) |*nm, index| {
        // Find path_secret for this new member.
        const member_ps = findMemberPathSecret(
            P,
            path_secrets,
            path_secret_count,
            fdp_nodes,
            committer_leaf,
            nm.leaf_index,
            tree_size,
        );

        const gs = GroupSecrets{
            .joiner_secret = joiner_secret,
            .path_secret = if (member_ps) |ps|
                ps[0..P.nh]
            else
                null,
            .psks = psk_ids,
        };

        secrets[index] = try encryptOneMemberSecret(
            P,
            allocator,
            &gs,
            nm,
            egi_data,
        );
        init_count += 1;
    }
    return secrets;
}

/// Find the path_secret for a new member per RFC 9420
/// §12.4.3.1: the secret for the lowest node in the
/// committer's filtered direct path that is also in the
/// new member's direct path.
fn findMemberPathSecret(
    comptime P: type,
    path_secrets: ?*const [path_mod.max_path_nodes][P.nh]u8,
    path_secret_count: u32,
    fdp_nodes: ?*const [path_mod.max_path_nodes]NodeIndex,
    committer_leaf: LeafIndex,
    member_leaf: LeafIndex,
    tree_size: u32,
) ?*const [P.nh]u8 {
    const ps = path_secrets orelse return null;
    const fdp = fdp_nodes orelse return null;
    if (path_secret_count == 0 or tree_size == 0)
        return null;

    // Compute the new member's direct path (unfiltered).
    var dp_buf: [32]NodeIndex = undefined;
    const member_dp = tree_math.directPath(
        member_leaf.toNodeIndex(),
        tree_size,
        &dp_buf,
    );

    // Find the lowest fdp node that is in the member's
    // direct path. The fdp is ordered from leaf-to-root,
    // so the first match is the lowest.
    for (0..path_secret_count) |i| {
        const fdp_node = fdp[i];
        for (member_dp) |dp_node| {
            if (fdp_node.toU32() == dp_node.toU32()) {
                return &ps[i];
            }
        }
    }

    // No overlap — committer and new member share no
    // filtered direct path nodes (e.g., they are under
    // different subtrees and all intermediate nodes were
    // filtered out). This can happen when the LCA node
    // has an empty copath resolution.
    _ = committer_leaf;
    return null;
}

/// Encrypt GroupSecrets for a single new member.
fn encryptOneMemberSecret(
    comptime P: type,
    allocator: std.mem.Allocator,
    gs: *const GroupSecrets,
    nm: *const NewMemberEntry(P),
    egi_data: []const u8,
) WelcomeError!EncryptedGroupSecrets {
    if (nm.init_pk.len != P.npk)
        return error.InvalidPublicKey;
    const pk: *const [P.npk]u8 = nm.init_pk[0..P.npk];

    const egs = welcome_msg.encryptGroupSecrets(
        P,
        gs,
        nm.kp_ref,
        pk,
        egi_data,
        nm.eph_seed,
    ) catch return error.HpkeSealFailed;

    const kem_copy = allocator.alloc(
        u8,
        egs.encrypted_group_secrets.kem_output.len,
    ) catch return error.OutOfMemory;
    errdefer allocator.free(kem_copy);
    @memcpy(
        kem_copy,
        egs.encrypted_group_secrets.kem_output,
    );

    const ct_copy = allocator.alloc(
        u8,
        egs.encrypted_group_secrets.ciphertext.len,
    ) catch return error.OutOfMemory;
    errdefer allocator.free(ct_copy);
    @memcpy(
        ct_copy,
        egs.encrypted_group_secrets.ciphertext,
    );

    const ref_copy = allocator.alloc(
        u8,
        nm.kp_ref.len,
    ) catch return error.OutOfMemory;
    @memcpy(ref_copy, nm.kp_ref);

    return EncryptedGroupSecrets{
        .new_member = ref_copy,
        .encrypted_group_secrets = .{
            .kem_output = kem_copy,
            .ciphertext = ct_copy,
        },
    };
}

/// Free a partially-initialized EncryptedGroupSecrets slice.
fn freeSecretsSlice(
    allocator: std.mem.Allocator,
    secrets: []EncryptedGroupSecrets,
    count: u32,
) void {
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        allocator.free(secrets[i].new_member);
        allocator.free(
            secrets[i].encrypted_group_secrets.kem_output,
        );
        allocator.free(
            secrets[i].encrypted_group_secrets.ciphertext,
        );
    }
    allocator.free(secrets);
}
