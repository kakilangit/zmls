//! GroupState and group creation per RFC 9420 Section 11.1.
//! Holds all mutable state (ratchet tree, context, epoch secrets,
//! transcript hashes) for a member's view of a group.
// Group creation per RFC 9420 Section 11.1.
//
// A group is created by a single member who initializes:
//   1. A RatchetTree with themselves at leaf 0.
//   2. A GroupContext at epoch 0.
//   3. Initial epoch secrets derived from all-zero init_secret.
//   4. Empty transcript hashes.
//
// The GroupState struct holds all mutable state for a member's
// view of a group. It is the central type for group operations.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const tree_hashes = @import("../tree/hashes.zig");
const tree_math = @import("../tree/math.zig");
const context_mod = @import("context.zig");
const schedule = @import("../key_schedule/schedule.zig");
const transcript = @import("../key_schedule/transcript.zig");
const auth_mod = @import("../framing/auth.zig");
const proposal_cache_mod = @import("proposal_cache.zig");
const epoch_key_ring_mod = @import(
    "../key_schedule/epoch_key_ring.zig",
);
const psk_lookup_mod = @import(
    "../key_schedule/psk_lookup.zig",
);
const commit_mod = @import("commit.zig");
const welcome_mod = @import("welcome.zig");
const external_mod = @import("external.zig");
const private_msg = @import("../framing/private_msg.zig");
const framing = @import("../framing/content_type.zig");
const framed_content_mod = @import(
    "../framing/framed_content.zig",
);
const proposal_mod = @import("../messages/proposal.zig");
const path_mod = @import("../tree/path.zig");
const evolution = @import("evolution.zig");

const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const Epoch = types.Epoch;
const LeafIndex = types.LeafIndex;
const NodeIndex = types.NodeIndex;
const LeafNode = node_mod.LeafNode;
const Extension = node_mod.Extension;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const max_gc_encode = context_mod.max_gc_encode;
const TreeError = errors.TreeError;
const CryptoError = errors.CryptoError;
const GroupError = errors.GroupError;

/// Maximum tree hash output size (for the largest supported hash).
const max_nh: u32 = 64;

// -- GroupState --------------------------------------------------------------

/// The full mutable state of a group member.
///
/// This struct holds the ratchet tree, the group context, epoch
/// secrets, and transcript hashes. It is updated on each commit.
///
/// GroupContext stores tree_hash and confirmed_transcript_hash
/// as inline [P.nh]u8 arrays, so no pointer fixup is needed
/// after struct moves.
pub fn GroupState(comptime P: type) type {
    return struct {
        /// The ratchet tree (heap-allocated nodes array).
        tree: RatchetTree,

        /// The group context for the current epoch.
        group_context: context_mod.GroupContext(P.nh),

        /// Epoch secrets derived from the key schedule.
        epoch_secrets: schedule.EpochSecrets(P),

        /// Interim transcript hash (between epochs).
        interim_transcript_hash: [P.nh]u8,

        /// Confirmed transcript hash (for current epoch).
        confirmed_transcript_hash: [P.nh]u8,

        /// This member's leaf index in the tree.
        my_leaf_index: LeafIndex,

        /// Wire format policy for outgoing messages.
        wire_format_policy: types.WireFormatPolicy,

        /// Pending proposals cache (cleared on epoch transition).
        pending_proposals: proposal_cache_mod.ProposalCache(P),

        /// Past-epoch secret retention ring buffer.
        epoch_key_ring: epoch_key_ring_mod.EpochKeyRing(P),

        /// Resumption PSK retention ring buffer.
        resumption_psk_ring: psk_lookup_mod.ResumptionPskRing(P),

        /// Allocator used for tree and group state.
        allocator: std.mem.Allocator,

        const Self = @This();

        /// Free all resources owned by this GroupState.
        pub fn deinit(self: *Self) void {
            self.tree.deinit();
            self.group_context.deinit(self.allocator);
            self.epoch_secrets.zeroize();
            self.epoch_key_ring.zeroAll();
            self.resumption_psk_ring.zeroAll();
            self.* = undefined;
        }

        /// Get the current epoch number.
        pub fn epoch(self: *const Self) Epoch {
            return self.group_context.epoch;
        }

        /// Get the cipher suite.
        pub fn cipherSuite(self: *const Self) CipherSuite {
            return self.group_context.cipher_suite;
        }

        /// Get the group ID.
        pub fn groupId(self: *const Self) []const u8 {
            return self.group_context.group_id;
        }

        /// Get the number of leaves in the tree.
        pub fn leafCount(self: *const Self) u32 {
            return self.tree.leaf_count;
        }

        /// Serialize the current group context.
        pub fn serializeContext(
            self: *const Self,
            buf: *[max_gc_encode]u8,
        ) ![]const u8 {
            return self.group_context.serialize(buf);
        }

        /// Return the current epoch's epoch_authenticator.
        ///
        /// Per RFC 9420 Section 8.7, this value is exported
        /// from the key schedule for use by applications
        /// (e.g., mutual authentication in higher protocols).
        pub fn epochAuthenticator(
            self: *const Self,
        ) *const [P.nh]u8 {
            return &self.epoch_secrets.epoch_authenticator;
        }

        // -- High-level method API (Phase 33.2) ----------

        /// Commit error union (re-exported for callers).
        pub const CommitError = commit_mod.CommitError;

        /// Create a Commit from this group state.
        ///
        /// Thin wrapper over `commit.createCommit` that
        /// extracts fields from `self`.
        pub fn createCommit(
            self: *const Self,
            allocator: std.mem.Allocator,
            opts: commit_mod.CreateCommitOpts(P),
        ) CommitError!commit_mod.CommitResult(P) {
            return commit_mod.createCommit(
                P,
                allocator,
                &self.group_context,
                &self.tree,
                self.my_leaf_index,
                opts.proposals,
                opts.sign_key,
                &self.interim_transcript_hash,
                &self.epoch_secrets.init_secret,
                opts.path_params,
                opts.psk_resolver,
                opts.wire_format,
            );
        }

        /// Process (verify + apply) a received Commit.
        ///
        /// Thin wrapper over `commit.processCommit` that
        /// extracts fields from `self`.
        pub fn processCommit(
            self: *const Self,
            allocator: std.mem.Allocator,
            opts: commit_mod.ProcessCommitOpts(P),
        ) CommitError!commit_mod.ProcessResult(P) {
            return commit_mod.processCommit(
                P,
                allocator,
                opts,
                &self.group_context,
                &self.tree,
                &self.interim_transcript_hash,
                &self.epoch_secrets.init_secret,
            );
        }

        /// Process a Welcome to join a group (static).
        ///
        /// No `self` — the group does not exist yet.
        pub fn joinViaWelcome(
            allocator: std.mem.Allocator,
            opts: welcome_mod.ProcessWelcomeOpts(P),
        ) welcome_mod.WelcomeError!Self {
            return welcome_mod.processWelcome(
                P,
                allocator,
                opts.welcome,
                opts.kp_ref,
                opts.init_sk,
                opts.init_pk,
                opts.signer_verify_key,
                opts.tree_data,
                opts.my_leaf_index,
                opts.psk_resolver,
            );
        }

        /// Create an external commit to join a group
        /// (static).
        ///
        /// No `self` — the joiner is not yet a member.
        pub fn joinViaExternalCommit(
            allocator: std.mem.Allocator,
            gc: *const context_mod.GroupContext(P.nh),
            tree: *const RatchetTree,
            gi_extensions: []const Extension,
            interim_th: *const [P.nh]u8,
            params: external_mod.ExternalCommitParams(P),
            wire_format: types.WireFormat,
        ) external_mod.ExternalCommitError!external_mod.ExternalCommitResult(P) {
            return external_mod.createExternalCommit(
                P,
                allocator,
                gc,
                tree,
                gi_extensions,
                interim_th,
                params,
                wire_format,
            );
        }

        /// Process a received external commit.
        pub fn processExternalCommit(
            self: *const Self,
            allocator: std.mem.Allocator,
            fc: *const framed_content_mod.FramedContent,
            signature: *const [P.sig_len]u8,
            confirmation_tag: *const [P.nh]u8,
            proposals: []const proposal_mod.Proposal,
            update_path: *const path_mod.UpdatePath,
            joiner_verify_key: *const [P.sign_pk_len]u8,
            external_secret: *const [P.nh]u8,
            psk_lookup: ?psk_lookup_mod.PskLookup,
            receiver_sk: *const [P.nsk]u8,
            receiver_pk: *const [P.npk]u8,
            wire_format: types.WireFormat,
        ) external_mod.ExternalCommitError!external_mod.ProcessExternalResult(P) {
            return external_mod.processExternalCommit(
                P,
                allocator,
                fc,
                signature,
                confirmation_tag,
                proposals,
                update_path,
                &self.group_context,
                &self.tree,
                joiner_verify_key,
                &self.interim_transcript_hash,
                external_secret,
                psk_lookup,
                self.my_leaf_index,
                receiver_sk,
                receiver_pk,
                wire_format,
            );
        }

        /// Encrypt application data (static helper).
        pub fn encryptContent(
            opts: private_msg.EncryptContentOpts(P),
            out: []u8,
        ) errors.CryptoError!u32 {
            return private_msg.encryptContent(
                P,
                opts.content,
                opts.content_type,
                opts.auth,
                opts.padding_block,
                opts.key,
                opts.nonce,
                opts.aad,
                out,
            );
        }

        /// Decrypt received content (static helper).
        pub fn decryptContent(
            ciphertext: []const u8,
            content_type: types.ContentType,
            key: *const [P.nk]u8,
            nonce: *const [P.nn]u8,
            aad: []const u8,
            pt_out: []u8,
        ) errors.CryptoError!private_msg.DecryptedContent(P) {
            return private_msg.decryptContent(
                P,
                ciphertext,
                content_type,
                key,
                nonce,
                aad,
                pt_out,
            );
        }

        /// Build a Welcome message for new members.
        pub fn buildWelcome(
            self: *const Self,
            allocator: std.mem.Allocator,
            opts: welcome_mod.BuildWelcomeOpts(P),
        ) welcome_mod.WelcomeError!welcome_mod.WelcomeResult {
            _ = self;
            return welcome_mod.buildWelcome(
                P,
                allocator,
                opts.gc_bytes,
                opts.confirmation_tag,
                opts.welcome_secret,
                opts.joiner_secret,
                opts.sign_key,
                opts.signer,
                opts.cipher_suite,
                opts.new_members,
                opts.psk_ids,
            );
        }

        // -- Unified output types (Phase 33.3) -----------

        /// Output of a commit creation. Contains the new
        /// group state plus data needed to send the commit
        /// and build a Welcome.
        pub const CommitOutput = struct {
            /// New group state for the next epoch.
            group_state: Self,
            /// Serialized Commit bytes.
            commit_bytes: [commit_mod.max_content_buf]u8,
            commit_len: u32,
            /// Signature over FramedContentTBS.
            signature: [P.sig_len]u8,
            /// Confirmation tag.
            confirmation_tag: [P.nh]u8,
            /// Joiner secret (for Welcome).
            joiner_secret: [P.nh]u8,
            /// Welcome secret (for Welcome).
            welcome_secret: [P.nh]u8,
            /// Leaf signature (for UpdatePath).
            leaf_sig: [P.sig_len]u8,
            /// Added leaves (for Welcome recipients).
            apply_result: evolution.ProposalApplyResult,

            pub fn deinit(self: *@This()) void {
                self.group_state.deinit();
                self.* = undefined;
            }
        };

        /// Output of processing a received commit.
        pub const ProcessOutput = struct {
            /// New group state for the next epoch.
            group_state: Self,

            pub fn deinit(self: *@This()) void {
                self.group_state.deinit();
                self.* = undefined;
            }
        };

        /// Create a commit and return a unified output
        /// containing the assembled new GroupState.
        pub fn commit(
            self: *const Self,
            allocator: std.mem.Allocator,
            opts: commit_mod.CreateCommitOpts(P),
        ) commit_mod.CommitError!CommitOutput {
            const cr = try commit_mod.createCommit(
                P,
                allocator,
                &self.group_context,
                &self.tree,
                self.my_leaf_index,
                opts.proposals,
                opts.sign_key,
                &self.interim_transcript_hash,
                &self.epoch_secrets.init_secret,
                opts.path_params,
                opts.psk_resolver,
                opts.wire_format,
            );
            // Assemble the new GroupState from result fields.
            return .{
                .group_state = .{
                    .tree = cr.tree,
                    .group_context = cr.group_context,
                    .epoch_secrets = cr.epoch_secrets,
                    .interim_transcript_hash = cr.interim_transcript_hash,
                    .confirmed_transcript_hash = cr.confirmed_transcript_hash,
                    .my_leaf_index = self.my_leaf_index,
                    .wire_format_policy = self.wire_format_policy,
                    .pending_proposals = proposal_cache_mod.ProposalCache(P).init(),
                    .epoch_key_ring = self.epoch_key_ring,
                    .resumption_psk_ring = self.resumption_psk_ring,
                    .allocator = allocator,
                },
                .commit_bytes = cr.commit_bytes,
                .commit_len = cr.commit_len,
                .signature = cr.signature,
                .confirmation_tag = cr.confirmation_tag,
                .joiner_secret = cr.joiner_secret,
                .welcome_secret = cr.welcome_secret,
                .leaf_sig = cr.leaf_sig,
                .apply_result = cr.apply_result,
            };
        }

        /// Process a received commit and return a unified
        /// output containing the assembled new GroupState.
        pub fn applyCommit(
            self: *const Self,
            allocator: std.mem.Allocator,
            opts: commit_mod.ProcessCommitOpts(P),
        ) commit_mod.CommitError!ProcessOutput {
            const cr = try commit_mod.processCommit(
                P,
                allocator,
                opts,
                &self.group_context,
                &self.tree,
                &self.interim_transcript_hash,
                &self.epoch_secrets.init_secret,
            );
            return .{
                .group_state = .{
                    .tree = cr.tree,
                    .group_context = cr.group_context,
                    .epoch_secrets = cr.epoch_secrets,
                    .interim_transcript_hash = cr.interim_transcript_hash,
                    .confirmed_transcript_hash = cr.confirmed_transcript_hash,
                    .my_leaf_index = self.my_leaf_index,
                    .wire_format_policy = self.wire_format_policy,
                    .pending_proposals = proposal_cache_mod.ProposalCache(P).init(),
                    .epoch_key_ring = self.epoch_key_ring,
                    .resumption_psk_ring = self.resumption_psk_ring,
                    .allocator = allocator,
                },
            };
        }
    };
}

// -- Group Creation ----------------------------------------------------------

/// Create a new group with a single member at epoch 0.
///
/// Per RFC 9420 Section 11.1:
///   1. Create a one-member tree with the creator at leaf 0.
///   2. Compute initial tree hash.
///   3. Build GroupContext at epoch 0 with empty transcript
///      hashes.
///   4. Derive epoch secrets from all-zero init_secret.
///
/// The `creator_leaf` must be a fully-formed LeafNode (with
/// source = .commit or .key_package).
///
/// The `group_id` is chosen by the creator.
pub fn createGroup(
    comptime P: type,
    allocator: std.mem.Allocator,
    group_id: []const u8,
    creator_leaf: LeafNode,
    cipher_suite: CipherSuite,
    group_extensions: []const Extension,
) (TreeError || CryptoError || error{OutOfMemory})!GroupState(P) {
    // 1. Create a one-member tree.
    var tree = try RatchetTree.init(allocator, 1);
    errdefer tree.deinit();

    try tree.setLeaf(LeafIndex.fromU32(0), creator_leaf);

    // 2. Compute tree hash.
    const root = tree_math.root(tree.leaf_count);
    const tree_hash = try tree_hashes.treeHash(
        P,
        allocator,
        &tree,
        root,
    );

    // 3. Clone group_id and extensions so GroupState owns them.
    //    GroupState.deinit() frees these via group_context.deinit.
    const owned_gid = try allocator.dupe(u8, group_id);
    errdefer allocator.free(owned_gid);

    const owned_exts = try cloneExtensions(
        allocator,
        group_extensions,
    );
    errdefer freeClonedExtensions(allocator, owned_exts);

    // 4. Build GroupContext at epoch 0.
    const zero_th: [P.nh]u8 = .{0} ** P.nh;

    const gc: context_mod.GroupContext(P.nh) = .{
        .version = .mls10,
        .cipher_suite = cipher_suite,
        .group_id = owned_gid,
        .epoch = 0,
        .tree_hash = tree_hash,
        .confirmed_transcript_hash = zero_th,
        .extensions = owned_exts,
    };

    // 5. Build the result struct.
    var result: GroupState(P) = .{
        .tree = tree,
        .group_context = gc,
        .epoch_secrets = undefined, // filled below
        .interim_transcript_hash = zero_th,
        .confirmed_transcript_hash = zero_th,
        .my_leaf_index = LeafIndex.fromU32(0),
        .wire_format_policy = .encrypt_application_only,
        .pending_proposals = proposal_cache_mod.ProposalCache(P).init(),
        .epoch_key_ring = epoch_key_ring_mod.EpochKeyRing(P).init(0),
        .resumption_psk_ring = psk_lookup_mod.ResumptionPskRing(P).init(0),
        .allocator = allocator,
    };

    // 6-8. Derive epoch secrets and interim transcript hash.
    deriveInitialEpoch(P, &result);

    return result;
}

/// Steps 6-8: Derive epoch-0 secrets and interim transcript
/// hash for a newly created group.
fn deriveInitialEpoch(
    comptime P: type,
    result: *GroupState(P),
) void {
    // 6. Serialize GroupContext for key schedule input.
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = result.group_context.serialize(
        &gc_buf,
    ) catch unreachable;

    // 7. Derive epoch secrets.
    //    At epoch 0: init_secret = 0, commit_secret = 0,
    //                psk_secret = 0.
    const zero: [P.nh]u8 = .{0} ** P.nh;
    result.epoch_secrets = schedule.deriveEpochSecrets(
        P,
        &zero, // init_secret
        &zero, // commit_secret
        &zero, // psk_secret
        gc_bytes,
    );

    // 8. Compute epoch-0 interim_transcript_hash per RFC 9420
    //    Section 8: confirmed_transcript_hash is all zeros,
    //    then confirmation_tag = MAC(confirmation_key, zeros),
    //    then interim = Hash(zeros || confirmation_tag).
    const conf_tag = auth_mod.computeConfirmationTag(
        P,
        &result.epoch_secrets.confirmation_key,
        &zero,
    );
    result.interim_transcript_hash =
        transcript.updateInterimTranscriptHash(
            P,
            &zero,
            &conf_tag,
        ) catch unreachable;
}

// -- Extension cloning helpers -----------------------------------------------

/// Deep-clone an extension list. Each extension's data is duped.
fn cloneExtensions(
    allocator: std.mem.Allocator,
    exts: []const Extension,
) error{OutOfMemory}![]const Extension {
    const owned = try allocator.alloc(Extension, exts.len);
    var init_count: u32 = 0;
    errdefer {
        var j: u32 = 0;
        while (j < init_count) : (j += 1) {
            allocator.free(owned[j].data);
        }
        allocator.free(owned);
    }
    for (exts, 0..) |ext, i| {
        const data_copy = try allocator.dupe(u8, ext.data);
        owned[i] = .{
            .extension_type = ext.extension_type,
            .data = data_copy,
        };
        init_count += 1;
    }
    return owned;
}

/// Free a cloned extension list.
fn freeClonedExtensions(
    allocator: std.mem.Allocator,
    exts: []const Extension,
) void {
    for (exts) |*ext| {
        allocator.free(ext.data);
    }
    allocator.free(exts);
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import(
    "../credential/credential.zig",
).Credential;

fn makeCreatorLeaf() LeafNode {
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]types.ExtensionType{};
    const prop_types = comptime [_]types.ProposalType{};
    const cred_types = comptime [_]types.CredentialType{.basic};

    return .{
        .encryption_key = &[_]u8{0x01} ** 32,
        .signature_key = &[_]u8{0x02} ** 32,
        .credential = Credential.initBasic("alice"),
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

test "createGroup produces a single-member group at epoch 0" {
    const alloc = testing.allocator;

    var gs = try createGroup(
        Default,
        alloc,
        "test-group-id",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    try testing.expectEqual(@as(u64, 0), gs.epoch());
    try testing.expectEqual(
        CipherSuite.mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        gs.cipherSuite(),
    );
    try testing.expectEqualSlices(
        u8,
        "test-group-id",
        gs.groupId(),
    );
    try testing.expectEqual(@as(u32, 1), gs.leafCount());
    try testing.expectEqual(
        @as(u32, 0),
        gs.my_leaf_index.toU32(),
    );
}

test "createGroup epoch secrets are non-zero" {
    const alloc = testing.allocator;

    var gs = try createGroup(
        Default,
        alloc,
        "group-2",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Epoch secrets should be non-zero.
    const zero = [_]u8{0} ** Default.nh;
    try testing.expect(!std.mem.eql(
        u8,
        &zero,
        &gs.epoch_secrets.epoch_secret,
    ));
    try testing.expect(!std.mem.eql(
        u8,
        &zero,
        &gs.epoch_secrets.init_secret,
    ));
}

test "createGroup tree has creator at leaf 0" {
    const alloc = testing.allocator;

    var gs = try createGroup(
        Default,
        alloc,
        "group-3",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    const leaf = try gs.tree.getLeaf(LeafIndex.fromU32(0));
    try testing.expect(leaf != null);
    try testing.expectEqualSlices(
        u8,
        "alice",
        leaf.?.credential.payload.basic,
    );
}

test "createGroup serializes context" {
    const alloc = testing.allocator;

    var gs = try createGroup(
        Default,
        alloc,
        "group-4",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    var buf: [max_gc_encode]u8 = undefined;
    const bytes = try gs.serializeContext(&buf);

    // Should be non-empty.
    try testing.expect(bytes.len > 20);
}

test "createGroup is deterministic" {
    const alloc = testing.allocator;

    var gs1 = try createGroup(
        Default,
        alloc,
        "det-group",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs1.deinit();

    var gs2 = try createGroup(
        Default,
        alloc,
        "det-group",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs2.deinit();

    // Same group_id + creator → same epoch secrets.
    try testing.expectEqualSlices(
        u8,
        &gs1.epoch_secrets.epoch_secret,
        &gs2.epoch_secrets.epoch_secret,
    );
}

test "epochAuthenticator is non-zero after createGroup" {
    const alloc = testing.allocator;

    const kp = try Default.signKeypairFromSeed(
        &[_]u8{0x01} ** 32,
    );
    const enc = try Default.dhKeypairFromSeed(
        &[_]u8{0x02} ** 32,
    );
    const leaf = node_mod.LeafNode{
        .encryption_key = &enc.pk,
        .signature_key = &kp.pk,
        .credential = .{
            .tag = .basic,
            .payload = .{ .basic = "user" },
        },
        .capabilities = .{
            .versions = &.{.mls10},
            .cipher_suites = &.{
                .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            },
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = null,
        .parent_hash = null,
        .extensions = &.{},
        .signature = &.{},
    };
    var gs = try createGroup(
        Default,
        alloc,
        "auth-test",
        leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    const ea = gs.epochAuthenticator();
    // Must not be all zero.
    const zero = [_]u8{0} ** Default.nh;
    try testing.expect(!std.mem.eql(u8, ea, &zero));
}
