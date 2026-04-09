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

const CipherSuite = types.CipherSuite;
const LeafIndex = types.LeafIndex;
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
) WelcomeError!GroupState(P) {
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

    // 7c. Verify joiner's leaf is present at my_leaf_index.
    const my_leaf = tree.getLeaf(my_leaf_index) catch
        return error.IndexOutOfRange;
    if (my_leaf == null) return error.InvalidLeafNode;

    // RFC 9420 S13.4: joiner must support all group extensions.
    try validateJoinerExtSupport(my_leaf.?.*, gc.extensions);

    // 8-10. Derive epoch secrets, verify confirmation.
    const epoch_out = try deriveWelcomeEpochState(
        P,
        &ws.joiner_secret,
        &ws.psk_secret,
        &gi,
        &gc,
    );

    // 11. Build GroupState.
    return try buildWelcomeGroupState(
        P,
        allocator,
        tree,
        &gc,
        epoch_out,
        my_leaf_index,
    );
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
    tree_hashes.verifyParentHashes(P, allocator, tree) catch
        return error.ParentHashMismatch;

    const root = tree_math.root(tree.leaf_count);
    const tree_hash = tree_hashes.treeHash(
        P,
        allocator,
        tree,
        root,
    ) catch return error.IndexOutOfRange;

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
fn validateTreeLeaves(
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
fn validateKeyUniqueness(
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
fn validateJoinerExtSupport(
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
fn encryptMemberSecrets(
    comptime P: type,
    allocator: std.mem.Allocator,
    joiner_secret: *const [P.nh]u8,
    psk_ids: []const psk_mod.PreSharedKeyId,
    new_members: []const NewMemberEntry(P),
    egi_data: []const u8,
) WelcomeError![]EncryptedGroupSecrets {
    const gs = GroupSecrets{
        .joiner_secret = joiner_secret,
        .path_secret = null,
        .psks = psk_ids,
    };

    const n_members: u32 = @intCast(new_members.len);
    const secrets = allocator.alloc(
        EncryptedGroupSecrets,
        n_members,
    ) catch return error.OutOfMemory;
    var init_count: u32 = 0;
    errdefer freeSecretsSlice(allocator, secrets, init_count);

    for (new_members, 0..) |*nm, index| {
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

// -- Tests ------------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import(
    "../credential/credential.zig",
).Credential;
const ProtocolVersion = types.ProtocolVersion;
const createGroup = state_mod.createGroup;
const createCommit = commit_mod.createCommit;
const proposal_mod = @import("../messages/proposal.zig");
const Proposal = proposal_mod.Proposal;
const key_package_mod = @import("../messages/key_package.zig");
const KeyPackage = key_package_mod.KeyPackage;
const codec = @import("../codec/codec.zig");
const path_mod = @import("../tree/path.zig");
const HPKECiphertext = path_mod.HPKECiphertext;

fn testSeed(tag: u8) [32]u8 {
    return [_]u8{tag} ** 32;
}

fn makeTestLeafWithKeys(
    enc_pk: []const u8,
    sig_pk: []const u8,
) LeafNode {
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]types.ExtensionType{};
    const prop_types = comptime [_]types.ProposalType{};
    const cred_types = comptime [_]types.CredentialType{.basic};

    return .{
        .encryption_key = enc_pk,
        .signature_key = sig_pk,
        .credential = Credential.initBasic(sig_pk),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &ext_types,
            .proposals = &prop_types,
            .credentials = &cred_types,
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
}

/// A KeyPackage with valid signature and distinct keys.
const TestKP = struct {
    kp: KeyPackage,
    sig_buf: [Default.sig_len]u8,
    leaf_sig_buf: [Default.sig_len]u8,
    enc_sk: [Default.nsk]u8,
    enc_pk: [Default.npk]u8,
    init_sk: [Default.nsk]u8,
    init_pk: [Default.npk]u8,
    sign_sk: [Default.sign_sk_len]u8,
    sign_pk: [Default.sign_pk_len]u8,

    /// Build a properly signed test KeyPackage in place.
    /// Caller must declare `var tkp: TestKP = undefined;`
    /// then call `try tkp.init(...)`. No fixup needed.
    fn init(
        self: *TestKP,
        enc_tag: u8,
        init_tag: u8,
        sign_tag: u8,
    ) !void {
        const enc_kp = try Default.dhKeypairFromSeed(
            &testSeed(enc_tag),
        );
        const init_kp = try Default.dhKeypairFromSeed(
            &testSeed(init_tag),
        );
        const sign_kp = try Default.signKeypairFromSeed(
            &testSeed(sign_tag),
        );

        self.enc_sk = enc_kp.sk;
        self.enc_pk = enc_kp.pk;
        self.init_sk = init_kp.sk;
        self.init_pk = init_kp.pk;
        self.sign_sk = sign_kp.sk;
        self.sign_pk = sign_kp.pk;

        self.kp = .{
            .version = .mls10,
            .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            .init_key = &self.init_pk,
            .leaf_node = makeTestLeafWithKeys(
                &self.enc_pk,
                &self.sign_pk,
            ),
            .extensions = &.{},
            .signature = &self.sig_buf,
        };
        self.kp.leaf_node.credential =
            Credential.initBasic(&self.sign_pk);
        self.kp.leaf_node.signature = &self.leaf_sig_buf;

        try self.kp.leaf_node.signLeafNode(
            Default,
            &self.sign_sk,
            &self.leaf_sig_buf,
            null,
            null,
        );
        try self.kp.signKeyPackage(
            Default,
            &self.sign_sk,
            &self.sig_buf,
        );
    }
};

/// Build a Welcome message from a CommitResult for testing.
///
/// This simulates what the committer would do after createCommit:
///   1. Serialize and sign GroupInfo.
///   2. Encrypt GroupInfo with welcome_secret.
///   3. Encrypt GroupSecrets for each new member.
///   4. Package into a Welcome.
fn buildTestWelcome(
    comptime P: type,
    allocator: std.mem.Allocator,
    commit_result: *commit_mod.CommitResult(P),
    sign_key: *const [P.sign_sk_len]u8,
    signer: u32,
    kp_ref: []const u8,
    init_pk: *const [P.npk]u8,
    eph_seed: *const [P.seed_len]u8,
    gc_bytes: []const u8,
) !TestWelcomeResult {
    // Steps 1-3: Sign, encode, encrypt GroupInfo.
    const egi_data = try encryptTestGroupInfo(
        P,
        allocator,
        commit_result,
        sign_key,
        signer,
        gc_bytes,
    );

    // 4. Encrypt GroupSecrets for the new member.
    const joiner = commit_result.epoch_secrets.joiner_secret;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = null,
        .psks = &.{},
    };

    const egs = try welcome_msg.encryptGroupSecrets(
        P,
        &gs,
        kp_ref,
        init_pk,
        egi_data,
        eph_seed,
    );

    // Copy encrypted group secrets fields to heap.
    const secrets = try copyGroupSecretsToHeap(
        allocator,
        &egs,
        kp_ref,
    );

    return .{
        .welcome = Welcome{
            .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            .secrets = secrets,
            .encrypted_group_info = egi_data,
        },
    };
}

/// Sign, encode, and encrypt GroupInfo for test Welcome.
fn encryptTestGroupInfo(
    comptime P: type,
    allocator: std.mem.Allocator,
    commit_result: *commit_mod.CommitResult(P),
    sign_key: *const [P.sign_sk_len]u8,
    signer: u32,
    gc_bytes: []const u8,
) ![]u8 {
    // 1. Sign GroupInfo.
    const sig = try group_info_mod.signGroupInfo(
        P,
        gc_bytes,
        &.{},
        &commit_result.confirmation_tag,
        signer,
        sign_key,
    );

    // 2. Encode the full GroupInfo.
    const gi = GroupInfo{
        .group_context = gc_bytes,
        .extensions = &.{},
        .confirmation_tag = &commit_result.confirmation_tag,
        .signer = signer,
        .signature = &sig,
    };

    var gi_buf: [max_gi_buf]u8 = undefined;
    const gi_end = try gi.encode(&gi_buf, 0);
    const gi_bytes = gi_buf[0..gi_end];

    // 3. Encrypt GroupInfo with welcome_secret.
    var egi_ct: [max_gi_buf]u8 = undefined;
    var egi_tag: [P.nt]u8 = undefined;
    group_info_mod.encryptGroupInfo(
        P,
        &commit_result.welcome_secret,
        gi_bytes,
        egi_ct[0..gi_end],
        &egi_tag,
    );

    // Build encrypted_group_info = ct || tag.
    const egi_len: u32 = gi_end + P.nt;
    const egi_data = try allocator.alloc(u8, egi_len);
    @memcpy(egi_data[0..gi_end], egi_ct[0..gi_end]);
    @memcpy(egi_data[gi_end..][0..P.nt], &egi_tag);
    return egi_data;
}

/// Copy EncryptedGroupSecrets fields to heap-allocated slices.
fn copyGroupSecretsToHeap(
    allocator: std.mem.Allocator,
    egs: *const welcome_msg.EncryptedGroupSecrets,
    kp_ref: []const u8,
) ![]EncryptedGroupSecrets {
    const kem_copy = try allocator.alloc(
        u8,
        egs.encrypted_group_secrets.kem_output.len,
    );
    errdefer allocator.free(kem_copy);
    @memcpy(
        kem_copy,
        egs.encrypted_group_secrets.kem_output,
    );

    const ct_copy = try allocator.alloc(
        u8,
        egs.encrypted_group_secrets.ciphertext.len,
    );
    errdefer allocator.free(ct_copy);
    @memcpy(
        ct_copy,
        egs.encrypted_group_secrets.ciphertext,
    );

    const ref_copy = try allocator.alloc(u8, kp_ref.len);
    errdefer allocator.free(ref_copy);
    @memcpy(ref_copy, kp_ref);

    const egs_heap = EncryptedGroupSecrets{
        .new_member = ref_copy,
        .encrypted_group_secrets = .{
            .kem_output = kem_copy,
            .ciphertext = ct_copy,
        },
    };

    const secrets = try allocator.alloc(
        EncryptedGroupSecrets,
        1,
    );
    secrets[0] = egs_heap;
    return secrets;
}

const TestWelcomeResult = struct {
    welcome: Welcome,

    fn deinit(self: *TestWelcomeResult, allocator: std.mem.Allocator) void {
        // Free secrets entries.
        for (self.welcome.secrets) |*egs| {
            allocator.free(egs.new_member);
            allocator.free(
                egs.encrypted_group_secrets.kem_output,
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

test "processWelcome: full create-commit-welcome-join flow" {
    const alloc = testing.allocator;

    // --- Setup: Alice creates a group ---
    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x01),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x02),
    );

    var gs = try createGroup(
        Default,
        alloc,
        "welcome-test-group",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_kp.pk),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // --- Setup: Bob's properly signed KeyPackage ---
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB0, 0xBB, 0xB2);

    // --- Alice commits to Add Bob ---
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Serialize the new GroupContext for GroupInfo.
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    // Compute Bob's KeyPackageRef.
    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    // --- Build Welcome for Bob ---
    const eph_seed = [_]u8{0xCC} ** 32;
    var tw = try buildTestWelcome(
        Default,
        alloc,
        &cr,
        &alice_kp.sk,
        0, // signer = alice at leaf 0
        &kp_ref,
        &bob_tkp.init_pk,
        &eph_seed,
        gc_bytes,
    );
    defer tw.deinit(alloc);

    // --- Bob processes the Welcome ---
    var bob_gs = try processWelcome(
        Default,
        alloc,
        &tw.welcome,
        &kp_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &alice_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1), // Bob is leaf 1
        null,
    );
    defer bob_gs.deinit();

    // --- Verify Bob's state matches Alice's ---
    // Same epoch.
    try testing.expectEqual(cr.new_epoch, bob_gs.epoch());

    // Same epoch secrets.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &bob_gs.epoch_secrets.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.init_secret,
        &bob_gs.epoch_secrets.init_secret,
    );

    // Same confirmation key.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.confirmation_key,
        &bob_gs.epoch_secrets.confirmation_key,
    );
}

test "processWelcome rejects wrong init key" {
    const alloc = testing.allocator;

    // Alice creates group.
    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x02),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x03),
    );

    var gs = try createGroup(
        Default,
        alloc,
        "welcome-wrong-key",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_kp.pk),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Wrong init key for decryption.
    const wrong_kp = try Default.dhKeypairFromSeed(
        &testSeed(0xEE),
    );

    // Bob's properly signed KeyPackage.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xD0, 0xDD, 0xD2);

    // Alice commits to Add Bob.
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    const eph_seed = [_]u8{0xFF} ** 32;
    var tw = try buildTestWelcome(
        Default,
        alloc,
        &cr,
        &alice_kp.sk,
        0,
        &kp_ref,
        &bob_tkp.init_pk,
        &eph_seed,
        gc_bytes,
    );
    defer tw.deinit(alloc);

    // Bob tries with wrong key — should fail.
    const result = processWelcome(
        Default,
        alloc,
        &tw.welcome,
        &kp_ref,
        &wrong_kp.sk,
        &wrong_kp.pk,
        &alice_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        null,
    );
    try testing.expectError(error.HpkeOpenFailed, result);
}

test "processWelcome rejects wrong signer key" {
    const alloc = testing.allocator;

    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x03),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x04),
    );

    var gs = try createGroup(
        Default,
        alloc,
        "welcome-wrong-signer",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_kp.pk),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x40, 0x44, 0x42);

    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    const eph_seed = [_]u8{0xFF} ** 32;
    var tw = try buildTestWelcome(
        Default,
        alloc,
        &cr,
        &alice_kp.sk,
        0,
        &kp_ref,
        &bob_tkp.init_pk,
        &eph_seed,
        gc_bytes,
    );
    defer tw.deinit(alloc);

    // Wrong signer key — should fail signature verification.
    const wrong_sign_kp = try Default.signKeypairFromSeed(
        &testSeed(0x99),
    );

    const result = processWelcome(
        Default,
        alloc,
        &tw.welcome,
        &kp_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &wrong_sign_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        null,
    );
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
}

test "processWelcome rejects wrong kp_ref" {
    const alloc = testing.allocator;

    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x04),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x05),
    );

    var gs = try createGroup(
        Default,
        alloc,
        "welcome-wrong-ref",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_kp.pk),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x60, 0x66, 0x62);

    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    const eph_seed = [_]u8{0x77} ** 32;
    var tw = try buildTestWelcome(
        Default,
        alloc,
        &cr,
        &alice_kp.sk,
        0,
        &kp_ref,
        &bob_tkp.init_pk,
        &eph_seed,
        gc_bytes,
    );
    defer tw.deinit(alloc);

    // Wrong kp_ref — no matching entry.
    const wrong_ref = [_]u8{0xFF} ** Default.nh;
    const result = processWelcome(
        Default,
        alloc,
        &tw.welcome,
        &wrong_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &alice_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        null,
    );
    try testing.expectError(
        error.NoMatchingKeyPackage,
        result,
    );
}

test "processWelcome: epoch secrets enable next commit" {
    const alloc = testing.allocator;

    // Full flow: Alice creates, adds Bob via Welcome,
    // then Bob uses the init_secret to process a second commit.
    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x05),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x06),
    );

    var gs = try createGroup(
        Default,
        alloc,
        "welcome-chain-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_kp.pk),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x80, 0x88, 0x82);

    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    const eph_seed = [_]u8{0x99} ** 32;
    var tw = try buildTestWelcome(
        Default,
        alloc,
        &cr,
        &alice_kp.sk,
        0,
        &kp_ref,
        &bob_tkp.init_pk,
        &eph_seed,
        gc_bytes,
    );
    defer tw.deinit(alloc);

    var bob_gs = try processWelcome(
        Default,
        alloc,
        &tw.welcome,
        &kp_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &alice_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        null,
    );
    defer bob_gs.deinit();

    // Bob's init_secret should match Alice's.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.init_secret,
        &bob_gs.epoch_secrets.init_secret,
    );

    // Both can derive the same next-epoch secrets.
    const zero_commit: [Default.nh]u8 = .{0} ** Default.nh;
    const zero_psk: [Default.nh]u8 = .{0} ** Default.nh;

    const alice_next = schedule.deriveEpochSecrets(
        Default,
        &cr.epoch_secrets.init_secret,
        &zero_commit,
        &zero_psk,
        gc_bytes,
    );
    const bob_next = schedule.deriveEpochSecrets(
        Default,
        &bob_gs.epoch_secrets.init_secret,
        &zero_commit,
        &zero_psk,
        gc_bytes,
    );

    try testing.expectEqualSlices(
        u8,
        &alice_next.epoch_secret,
        &bob_next.epoch_secret,
    );
}

test "processWelcome rejects tampered encrypted_group_info" {
    const alloc = testing.allocator;

    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x06),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x07),
    );

    var gs = try createGroup(
        Default,
        alloc,
        "welcome-tamper-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_kp.pk),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xA0, 0xAA, 0xA2);

    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals_arr = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals_arr,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    const eph_seed = [_]u8{0xBB} ** 32;
    var tw = try buildTestWelcome(
        Default,
        alloc,
        &cr,
        &alice_kp.sk,
        0,
        &kp_ref,
        &bob_tkp.init_pk,
        &eph_seed,
        gc_bytes,
    );
    defer tw.deinit(alloc);

    // Tamper with encrypted_group_info.
    const egi_mut: []u8 = @constCast(
        tw.welcome.encrypted_group_info,
    );
    if (egi_mut.len > 0) {
        egi_mut[0] ^= 0xFF;
    }

    // Tampering with encrypted_group_info causes HPKE
    // decryption of GroupSecrets to fail because
    // encrypted_group_info is used as HPKE info/context
    // in EncryptWithLabel.
    const result = processWelcome(
        Default,
        alloc,
        &tw.welcome,
        &kp_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &alice_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        null,
    );
    try testing.expectError(error.HpkeOpenFailed, result);
}

test "processWelcome rejects wrong my_leaf_index" {
    const alloc = testing.allocator;

    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x16),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x17),
    );

    var gs = try createGroup(
        Default,
        alloc,
        "welcome-wrong-leaf",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_kp.pk),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xA0, 0xAA, 0xA2);

    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    const eph_seed = [_]u8{0xFF} ** 32;
    var tw = try buildTestWelcome(
        Default,
        alloc,
        &cr,
        &alice_kp.sk,
        0,
        &kp_ref,
        &bob_tkp.init_pk,
        &eph_seed,
        gc_bytes,
    );
    defer tw.deinit(alloc);

    // Pass out-of-range leaf index (tree has 2 members).
    const result = processWelcome(
        Default,
        alloc,
        &tw.welcome,
        &kp_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &alice_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(5),
        null,
    );
    try testing.expectError(error.IndexOutOfRange, result);
}

test "buildWelcome round-trip with processWelcome" {
    const alloc = testing.allocator;

    // Alice's real signing and encryption keys.
    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x10),
    );
    const alice_enc_kp = try Default.dhKeypairFromSeed(
        &testSeed(0x11),
    );

    // Bob's properly signed KeyPackage.
    // enc=0x20, init=0x21, sign=0x22 (all distinct).
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x20, 0x21, 0x22);

    // Alice creates group with real keys.
    const alice_leaf = makeTestLeafWithKeys(
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );

    var gs = try createGroup(
        Default,
        alloc,
        "buildwelcome-test",
        alice_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Alice commits to Add Bob.
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Serialize new GroupContext.
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    // Compute Bob's KeyPackageRef.
    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    // Build Welcome using the public buildWelcome API.
    const eph_seed = [_]u8{0xDD} ** 32;
    const nm = [_]NewMemberEntry(Default){.{
        .kp_ref = &kp_ref,
        .init_pk = &bob_tkp.init_pk,
        .eph_seed = &eph_seed,
    }};

    var wr = try buildWelcome(
        Default,
        alloc,
        gc_bytes,
        &cr.confirmation_tag,
        &cr.welcome_secret,
        &cr.joiner_secret,
        &alice_kp.sk,
        0, // alice = signer leaf 0
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &nm,
        &.{},
    );
    defer wr.deinit(alloc);

    // Bob processes the Welcome.
    var bob_gs = try processWelcome(
        Default,
        alloc,
        &wr.welcome,
        &kp_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &alice_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        null,
    );
    defer bob_gs.deinit();

    // Verify: same epoch.
    try testing.expectEqual(cr.new_epoch, bob_gs.epoch());

    // Verify: same epoch secrets.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &bob_gs.epoch_secrets.epoch_secret,
    );

    // Verify: same confirmation key.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.confirmation_key,
        &bob_gs.epoch_secrets.confirmation_key,
    );

    // Verify: same init secret (for next epoch).
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.init_secret,
        &bob_gs.epoch_secrets.init_secret,
    );
}

test "Welcome with external PSK decrypts correctly" {
    const alloc = testing.allocator;

    // Alice's keys.
    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x30),
    );
    const alice_enc_kp = try Default.dhKeypairFromSeed(
        &testSeed(0x31),
    );

    // Bob's KeyPackage.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x40, 0x41, 0x42);

    // Shared external PSK known to both Alice and Bob.
    var psk_store = psk_lookup_mod.InMemoryPskStore.init();
    const ext_secret = [_]u8{0xBB} ** 32;
    _ = psk_store.addPsk("shared-psk", &ext_secret);

    var res_ring = psk_lookup_mod.ResumptionPskRing(
        Default,
    ).init(0);
    const resolver: commit_mod.PskResolver(Default) = .{
        .external = psk_store.lookup(),
        .resumption = &res_ring,
    };

    // Alice creates group.
    const alice_leaf = makeTestLeafWithKeys(
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );
    var gs = try createGroup(
        Default,
        alloc,
        "psk-welcome-test",
        alice_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // PSK proposal + Add(Bob).
    const psk_id = psk_mod.PreSharedKeyId{
        .psk_type = .external,
        .external_psk_id = "shared-psk",
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = &([_]u8{0x03} ** 32),
    };
    const psk_prop = Proposal{
        .tag = .psk,
        .payload = .{ .psk = .{ .psk = psk_id } },
    };
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{ psk_prop, add_prop };

    // Alice commits with PSK resolver.
    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null, // Add+PSK: no path needed
        resolver,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Serialize new GroupContext.
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    // Compute Bob's KeyPackageRef.
    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    // Build Welcome with the PSK ID in GroupSecrets.
    const eph_seed = [_]u8{0xEE} ** 32;
    const nm = [_]NewMemberEntry(Default){.{
        .kp_ref = &kp_ref,
        .init_pk = &bob_tkp.init_pk,
        .eph_seed = &eph_seed,
    }};
    const psk_ids = [_]psk_mod.PreSharedKeyId{psk_id};

    var wr = try buildWelcome(
        Default,
        alloc,
        gc_bytes,
        &cr.confirmation_tag,
        &cr.welcome_secret,
        &cr.joiner_secret,
        &alice_kp.sk,
        0,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &nm,
        &psk_ids,
    );
    defer wr.deinit(alloc);

    // Bob processes Welcome with same PSK store.
    var bob_gs = try processWelcome(
        Default,
        alloc,
        &wr.welcome,
        &kp_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &alice_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        resolver,
    );
    defer bob_gs.deinit();

    // Both sides agree on epoch.
    try testing.expectEqual(cr.new_epoch, bob_gs.epoch());

    // Both sides agree on epoch secrets.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &bob_gs.epoch_secrets.epoch_secret,
    );

    // Both sides agree on confirmation key.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.confirmation_key,
        &bob_gs.epoch_secrets.confirmation_key,
    );
}

test "processWelcome rejects cipher suite mismatch" {
    const alloc = testing.allocator;

    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0x50),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x51),
    );

    var gs = try createGroup(
        Default,
        alloc,
        "suite-mismatch-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_kp.pk),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x52, 0x53, 0x54);

    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    const eph_seed = [_]u8{0x55} ** 32;
    var tw = try buildTestWelcome(
        Default,
        alloc,
        &cr,
        &alice_kp.sk,
        0,
        &kp_ref,
        &bob_tkp.init_pk,
        &eph_seed,
        gc_bytes,
    );
    defer tw.deinit(alloc);

    // Tamper: set a different cipher suite on the Welcome.
    tw.welcome.cipher_suite =
        .mls_256_dhkemx448_aes256gcm_sha512_ed448;

    const result = processWelcome(
        Default,
        alloc,
        &tw.welcome,
        &kp_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &alice_kp.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        null,
    );
    try testing.expectError(
        error.CipherSuiteMismatch,
        result,
    );
}

test "validateTreeLeaves rejects invalid leaf" {
    const alloc = testing.allocator;

    // Build a 2-leaf tree. The second leaf has an empty
    // cipher_suites list, which makes validate() fail.
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    const enc_a = try Default.dhKeypairFromSeed(
        &testSeed(0x60),
    );
    const sig_a = try Default.signKeypairFromSeed(
        &testSeed(0x61),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafWithKeys(&enc_a.pk, &sig_a.pk),
    );

    // Second leaf: empty cipher_suites makes validate fail.
    var bad_leaf = makeTestLeafWithKeys(
        &(try Default.dhKeypairFromSeed(&testSeed(0x62))).pk,
        &(try Default.signKeypairFromSeed(&testSeed(0x63))).pk,
    );
    const empty_suites = [_]CipherSuite{};
    bad_leaf.capabilities.cipher_suites = &empty_suites;
    try tree.setLeaf(LeafIndex.fromU32(1), bad_leaf);

    const result = validateTreeLeaves(
        &tree,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    );
    try testing.expectError(error.InvalidLeafNode, result);
}

test "validateKeyUniqueness rejects duplicate enc keys" {
    const alloc = testing.allocator;

    // Build a 2-leaf tree where both leaves share the same
    // encryption key.
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    const shared_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x70),
    );
    const sig_a = try Default.signKeypairFromSeed(
        &testSeed(0x71),
    );
    const sig_b = try Default.signKeypairFromSeed(
        &testSeed(0x72),
    );

    // Both leaves use the same encryption key.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafWithKeys(&shared_enc.pk, &sig_a.pk),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafWithKeys(&shared_enc.pk, &sig_b.pk),
    );

    const result = validateKeyUniqueness(&tree);
    try testing.expectError(error.InvalidLeafNode, result);
}

test "validateJoinerExtSupport rejects unsupported extension" {
    const enc = try Default.dhKeypairFromSeed(&testSeed(0x80));
    const sig = try Default.signKeypairFromSeed(&testSeed(0x81));
    var leaf = makeTestLeafWithKeys(&enc.pk, &sig.pk);

    // Leaf has empty extensions capability list.
    // Group uses a non-default extension type (last_resort = 10).
    const gc_exts = [_]Extension{.{
        .extension_type = .last_resort,
        .data = &.{},
    }};

    // Joiner does not list last_resort -> must fail.
    try testing.expectError(
        error.UnsupportedCapability,
        validateJoinerExtSupport(leaf, &gc_exts),
    );

    // After adding last_resort to capabilities, it should pass.
    const supported = [_]types.ExtensionType{.last_resort};
    leaf.capabilities.extensions = &supported;
    try validateJoinerExtSupport(leaf, &gc_exts);
}

test "validateJoinerExtSupport allows default extension types" {
    const enc = try Default.dhKeypairFromSeed(&testSeed(0x82));
    const sig = try Default.signKeypairFromSeed(&testSeed(0x83));
    const leaf = makeTestLeafWithKeys(&enc.pk, &sig.pk);

    // Group uses only default extensions (types 1-5).
    // Joiner has empty capabilities.extensions but should pass
    // because 1-5 are implicitly supported.
    const gc_exts = [_]Extension{
        .{ .extension_type = .application_id, .data = &.{} },
        .{ .extension_type = .ratchet_tree, .data = &.{} },
        .{ .extension_type = .required_capabilities, .data = &.{} },
        .{ .extension_type = .external_pub, .data = &.{} },
        .{ .extension_type = .external_senders, .data = &.{} },
    };

    try validateJoinerExtSupport(leaf, &gc_exts);
}

test "verifyParentHashes rejects tampered tree in welcome context" {
    const alloc = testing.allocator;

    // Build a 2-leaf tree with commit-source leaf 0.
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    const enc_a = try Default.dhKeypairFromSeed(&testSeed(0x90));
    const sig_a = try Default.signKeypairFromSeed(&testSeed(0x91));
    const enc_b = try Default.dhKeypairFromSeed(&testSeed(0x92));
    const sig_b = try Default.signKeypairFromSeed(&testSeed(0x93));

    var leaf_a = makeTestLeafWithKeys(&enc_a.pk, &sig_a.pk);
    leaf_a.source = .commit;

    try tree.setLeaf(LeafIndex.fromU32(1), makeTestLeafWithKeys(
        &enc_b.pk,
        &sig_b.pk,
    ));

    // Set root parent node.
    const root_enc = try Default.dhKeypairFromSeed(&testSeed(0x94));
    const tree_mod = @import("../tree/node.zig");
    try tree.setNode(
        types.NodeIndex.fromU32(1),
        tree_mod.Node.initParent(.{
            .encryption_key = &root_enc.pk,
            .parent_hash = "",
            .unmerged_leaves = &.{},
        }),
    );

    // Set correct parent_hash on leaf_a.
    var ph_buf: [Default.nh]u8 = undefined;
    if (try path_mod.computeLeafParentHash(
        Default,
        testing.allocator,
        &tree,
        LeafIndex.fromU32(0),
    )) |ph| {
        ph_buf = ph;
        leaf_a.parent_hash = &ph_buf;
    }
    try tree.setLeaf(LeafIndex.fromU32(0), leaf_a);

    // Should pass.
    try tree_hashes.verifyParentHashes(Default, testing.allocator, &tree);

    // Tamper: flip a byte in the leaf's parent_hash.
    const slot = &tree.nodes[0];
    const lp = &slot.*.?.payload.leaf;
    if (lp.parent_hash) |ph| {
        @constCast(ph)[0] ^= 0xFF;
    }

    // Should fail.
    const result = tree_hashes.verifyParentHashes(Default, testing.allocator, &tree);
    try testing.expectError(error.ParentHashMismatch, result);
}
