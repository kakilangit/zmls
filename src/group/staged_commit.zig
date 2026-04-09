//! Two-phase staged commit (stage then apply/discard) per
//! RFC 9420 Section 12.4. Eagerly computes new epoch state
//! that can be cheaply swapped into GroupState.
// Staged commit (two-phase apply) per RFC 9420 Section 12.4.
//
// Design: stageCommit eagerly computes the full new state (same
// as processCommit). apply() is a cheap swap of the staged state
// into GroupState. discard() frees the staged state and zeros
// secrets. No deferred computation.
//
// Usage:
//   var staged = try stageCommit(P, fc, sig, tag, ...);
//   // inspect staged.result if desired
//   try staged.apply(&group_state);
//   // OR
//   try staged.discard();

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");
const context_mod = @import("context.zig");
const state_mod = @import("state.zig");
const commit_mod = @import("commit.zig");
const schedule = @import("../key_schedule/schedule.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const evolution = @import("evolution.zig");
const proposal_cache_mod = @import("proposal_cache.zig");
const primitives = @import("../crypto/primitives.zig");

const secureZero = primitives.secureZero;
const Epoch = types.Epoch;
const LeafIndex = types.LeafIndex;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const GroupState = state_mod.GroupState;
const ProcessResult = commit_mod.ProcessResult;
const CommitError = commit_mod.CommitError;
const ProposalApplyResult = evolution.ProposalApplyResult;

/// A staged commit holding the pending new state before it is
/// applied to a GroupState.
///
/// The caller can inspect the result (new epoch, added/removed
/// members, etc.) and then either call `apply()` to finalize
/// or `discard()` to abandon.
pub fn StagedCommit(comptime P: type) type {
    return struct {
        /// The computed new state from processCommit.
        result: ProcessResult(P),

        /// Whether this staged commit has been consumed.
        consumed: bool,

        const Self = @This();

        /// Apply the staged commit to a GroupState, advancing
        /// it to the new epoch.
        ///
        /// After apply, the old tree is freed and the old epoch
        /// secrets are zeroed. The proposal cache is cleared.
        /// The outgoing epoch's sender_data_secret is retained
        /// in the epoch key ring for past-epoch decryption.
        pub fn apply(self: *Self, gs: *GroupState(P)) error{AlreadyConsumed}!void {
            if (self.consumed) return error.AlreadyConsumed;
            self.consumed = true;

            // Retain outgoing epoch secrets before zeroing.
            gs.epoch_key_ring.retain(
                gs.group_context.epoch,
                &gs.epoch_secrets.sender_data_secret,
            );

            // Retain outgoing resumption PSK.
            gs.resumption_psk_ring.retain(
                gs.group_context.epoch,
                &gs.epoch_secrets.resumption_psk,
            );

            // Free old tree and group context heap data.
            gs.tree.deinit();
            gs.group_context.deinit(gs.allocator);

            // Zero old epoch secrets.
            gs.epoch_secrets.zeroize();

            // Swap in new state.
            gs.tree = self.result.tree;
            gs.group_context = self.result.group_context;
            gs.epoch_secrets = self.result.epoch_secrets;
            gs.confirmed_transcript_hash =
                self.result.confirmed_transcript_hash;
            gs.interim_transcript_hash =
                self.result.interim_transcript_hash;

            // Clear pending proposals for the new epoch.
            gs.pending_proposals.clear();
        }

        /// Discard the staged commit without applying it.
        ///
        /// Frees the staged tree and zeros the staged epoch
        /// secrets. The original GroupState is unchanged.
        pub fn discard(
            self: *Self,
            allocator: std.mem.Allocator,
        ) error{AlreadyConsumed}!void {
            if (self.consumed) return error.AlreadyConsumed;
            self.consumed = true;

            self.result.tree.deinit();
            self.result.group_context.deinit(allocator);
            self.result.epoch_secrets.zeroize();
        }

        /// Get the new epoch number.
        pub fn newEpoch(self: *const Self) Epoch {
            return self.result.new_epoch;
        }

        /// Get the apply result (added/removed members).
        pub fn applyResult(
            self: *const Self,
        ) ProposalApplyResult {
            return self.result.apply_result;
        }
    };
}

/// Stage a commit for two-phase apply.
///
/// This performs the same validation and derivation as
/// processCommit but returns a StagedCommit instead of
/// immediately mutating the GroupState.
///
/// The caller must then call either `staged.apply(&gs)` or
/// `staged.discard()` to finalize.
pub fn stageCommit(
    comptime P: type,
    allocator: std.mem.Allocator,
    opts: commit_mod.ProcessCommitOpts(P),
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
    interim_transcript_hash: *const [P.nh]u8,
    init_secret: *const [P.nh]u8,
) CommitError!StagedCommit(P) {
    const result = try commit_mod.processCommit(
        P,
        allocator,
        opts,
        group_context,
        tree,
        interim_transcript_hash,
        init_secret,
    );
    return .{
        .result = result,
        .consumed = false,
    };
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import(
    "../credential/credential.zig",
).Credential;
const node_mod = @import("../tree/node.zig");
const proposal_mod = @import("../messages/proposal.zig");
const framing = @import("../framing/content_type.zig");
const framed_content_mod = @import(
    "../framing/framed_content.zig",
);
const key_package_mod = @import(
    "../messages/key_package.zig",
);

const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const Proposal = proposal_mod.Proposal;
const Sender = framing.Sender;
const FramedContent = framed_content_mod.FramedContent;
const KeyPackage = key_package_mod.KeyPackage;

fn makeTestLeaf(
    enc_pk: []const u8,
    sig_pk: []const u8,
) node_mod.LeafNode {
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

fn testSeed(tag: u8) [32]u8 {
    return [_]u8{tag} ** 32;
}

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
            .leaf_node = makeTestLeaf(
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

const TestGroup = struct {
    gs: GroupState(Default),
    sign_sk: [Default.sign_sk_len]u8,
    sign_pk: [Default.sign_pk_len]u8,
    enc_sk: [Default.nsk]u8,
    enc_pk: [Default.npk]u8,

    fn deinit(self: *TestGroup) void {
        self.gs.deinit();
    }

    fn init(
        self: *TestGroup,
        allocator: std.mem.Allocator,
    ) !void {
        const alice_sign = try Default.signKeypairFromSeed(
            &testSeed(0x42),
        );
        const alice_enc = try Default.dhKeypairFromSeed(
            &testSeed(0xA0),
        );
        self.sign_sk = alice_sign.sk;
        self.sign_pk = alice_sign.pk;
        self.enc_sk = alice_enc.sk;
        self.enc_pk = alice_enc.pk;
        self.gs = try state_mod.createGroup(
            Default,
            allocator,
            "test-group",
            makeTestLeaf(&self.enc_pk, &self.sign_pk),
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            &.{},
        );
    }
};

test "stageCommit then apply advances group state" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    // Creator creates the commit.
    var cr = try commit_mod.createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    // Stage the commit.
    var staged = try stageCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &proposals,
            .sender_verify_key = &tg.sign_pk,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );

    // Inspect before apply.
    try testing.expectEqual(@as(u64, 1), staged.newEpoch());
    try testing.expectEqual(
        @as(u32, 1),
        staged.applyResult().added_count,
    );

    // Original state is still at epoch 0.
    try testing.expectEqual(@as(u64, 0), tg.gs.epoch());

    // Apply.
    try staged.apply(&tg.gs);

    // Group state is now at epoch 1 with 2 leaves.
    try testing.expectEqual(@as(u64, 1), tg.gs.epoch());
    try testing.expectEqual(@as(u32, 2), tg.gs.leafCount());
}

test "stageCommit then discard leaves state unchanged" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Save original epoch secrets for comparison.
    const orig_epoch_secret = tg.gs.epoch_secrets.epoch_secret;
    const orig_tree_hash = tg.gs.group_context.tree_hash;

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try commit_mod.createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    var staged = try stageCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &proposals,
            .sender_verify_key = &tg.sign_pk,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );

    // Discard.
    try staged.discard(testing.allocator);

    // Original state is unchanged.
    try testing.expectEqual(@as(u64, 0), tg.gs.epoch());
    try testing.expectEqual(@as(u32, 1), tg.gs.leafCount());
    try testing.expectEqualSlices(
        u8,
        &orig_epoch_secret,
        &tg.gs.epoch_secrets.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &orig_tree_hash,
        &tg.gs.group_context.tree_hash,
    );
}

test "apply retains past-epoch sender_data_secret in ring" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Enable retention of 3 past epochs.
    tg.gs.epoch_key_ring.capacity = 3;

    // Save epoch 0 sender_data_secret for later comparison.
    const sds_epoch0 = tg.gs.epoch_secrets.sender_data_secret;

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try commit_mod.createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    var staged = try stageCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &proposals,
            .sender_verify_key = &tg.sign_pk,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );

    try staged.apply(&tg.gs);

    // Now at epoch 1.
    try testing.expectEqual(@as(u64, 1), tg.gs.epoch());

    // Epoch 0 sender_data_secret should be retained.
    const retained = tg.gs.epoch_key_ring.lookup(0);
    try testing.expect(retained != null);
    try testing.expectEqualSlices(
        u8,
        &sds_epoch0,
        retained.?,
    );

    // Current epoch (1) is NOT in the ring — it is live.
    try testing.expect(tg.gs.epoch_key_ring.lookup(1) == null);
}
