const std = @import("std");
const testing = std.testing;

const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const context_mod = @import("context.zig");
const evolution = @import("evolution.zig");
const transcript = @import("../key_schedule/transcript.zig");
const psk_lookup_mod = @import("../key_schedule/psk_lookup.zig");
const framing = @import("../framing/content_type.zig");
const framed_content_mod = @import("../framing/framed_content.zig");
const auth_mod = @import("../framing/auth.zig");
const proposal_mod = @import("../messages/proposal.zig");
const commit_msg = @import("../messages/commit.zig");
const path_mod = @import("../tree/path.zig");
const public_msg = @import("../framing/public_msg.zig");
const tree_hashes = @import("../tree/hashes.zig");
const state_mod = @import("state.zig");
const commit = @import("commit.zig");

const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import(
    "../credential/credential.zig",
).Credential;
const KeyPackage = @import(
    "../messages/key_package.zig",
).KeyPackage;

const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const LeafIndex = types.LeafIndex;
const NodeIndex = types.NodeIndex;
const Epoch = types.Epoch;
const Proposal = proposal_mod.Proposal;
const Commit = commit_msg.Commit;
const UpdatePath = path_mod.UpdatePath;
const FramedContent = framed_content_mod.FramedContent;
const Sender = framing.Sender;
const ValidatedProposals = evolution.ValidatedProposals;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const max_gc_encode = context_mod.max_gc_encode;
const GroupState = state_mod.GroupState;
const createGroup = state_mod.createGroup;
const createCommit = commit.createCommit;
const processCommit = commit.processCommit;
const CommitResult = commit.CommitResult;
const ProcessResult = commit.ProcessResult;
const PathParams = commit.PathParams;
const ReceiverPathParams = commit.ReceiverPathParams;
const PskResolver = commit.PskResolver;
const isPathRequired = commit.isPathRequired;
const CommitError = commit.CommitError;

// ── Test helpers ────────────────────────────────────────────

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

fn makeTestLeafWithPk(
    id: []const u8,
    enc_pk: []const u8,
    sig_pk: []const u8,
) node_mod.LeafNode {
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]types.ExtensionType{};
    const prop_types = comptime [_]types.ProposalType{};
    const cred_types = comptime [_]types.CredentialType{
        .basic,
    };

    return .{
        .encryption_key = enc_pk,
        .signature_key = sig_pk,
        .credential = Credential.initBasic(id),
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

/// Deterministic seed derivation from a u8 tag.
fn testSeed(tag: u8) [32]u8 {
    return [_]u8{tag} ** 32;
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
    /// `enc_tag` and `init_tag` must differ so that
    /// init_key != encryption_key (Section 10.1 rule 4).
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

        // Sign leaf node first (key_package source: no
        // group context).
        try self.kp.leaf_node.signLeafNode(
            Default,
            &self.sign_sk,
            &self.leaf_sig_buf,
            null,
            null,
        );
        // Then sign the KeyPackage.
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
        self.* = undefined;
    }

    /// Init in-place so leaf node slices point directly at
    /// this struct's owned arrays (no move, no fixup).
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
        self.gs = try createGroup(
            Default,
            allocator,
            "test-group",
            makeTestLeaf(&self.enc_pk, &self.sign_pk),
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            &.{},
        );
    }
};

// ── Tests ───────────────────────────────────────────────────

test "createCommit with Add proposal advances epoch" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var result = try createCommit(
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
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // New epoch should be 1.
    try testing.expectEqual(@as(u64, 1), result.new_epoch);

    // Tree should now have 2 leaves (alice + bob).
    try testing.expectEqual(
        @as(u32, 2),
        result.tree.leaf_count,
    );

    // One member was added.
    try testing.expectEqual(
        @as(u32, 1),
        result.apply_result.added_count,
    );
}

test "createCommit produces non-zero confirmation tag" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var carol_kp: TestKP = undefined;
    try carol_kp.init(0xC0, 0xC1, 0xC2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = carol_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var result = try createCommit(
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
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // Confirmation tag should be non-zero.
    const zero = [_]u8{0} ** Default.nh;
    try testing.expect(
        !std.mem.eql(u8, &zero, &result.confirmation_tag),
    );
}

test "createCommit produces non-zero epoch secrets" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    const proposals = [_]Proposal{};

    var result = try createCommit(
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
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // Epoch secrets should differ from epoch 0.
    try testing.expect(
        !std.mem.eql(
            u8,
            &tg.gs.epoch_secrets.epoch_secret,
            &result.epoch_secrets.epoch_secret,
        ),
    );
}

test "createCommit is deterministic" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var dave_kp: TestKP = undefined;
    try dave_kp.init(0xD0, 0xD1, 0xD2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = dave_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var r1 = try createCommit(
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
    defer r1.tree.deinit();
    defer r1.deinit(testing.allocator);

    var r2 = try createCommit(
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
    defer r2.tree.deinit();
    defer r2.deinit(testing.allocator);

    // Same inputs → same outputs.
    try testing.expectEqualSlices(
        u8,
        &r1.confirmation_tag,
        &r2.confirmation_tag,
    );
    try testing.expectEqualSlices(
        u8,
        &r1.signature,
        &r2.signature,
    );
    try testing.expectEqualSlices(
        u8,
        &r1.confirmed_transcript_hash,
        &r2.confirmed_transcript_hash,
    );
}

test "createCommit with multiple Adds" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    var carol_kp: TestKP = undefined;
    try carol_kp.init(0xC0, 0xC1, 0xC2);
    var dave_kp: TestKP = undefined;
    try dave_kp.init(0xD0, 0xD1, 0xD2);

    const proposals = [_]Proposal{
        .{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = bob_kp.kp,
                },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = carol_kp.kp,
                },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = dave_kp.kp,
                },
            },
        },
    };

    var result = try createCommit(
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
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // Tree should have 4 leaves now.
    try testing.expectEqual(
        @as(u32, 4),
        result.tree.leaf_count,
    );
    try testing.expectEqual(
        @as(u32, 3),
        result.apply_result.added_count,
    );
}

test "createCommit transcript hashes form a chain" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // First commit (epoch 0 → 1).
    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const p1 = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    }};

    var r1 = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &p1,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer r1.tree.deinit();
    defer r1.deinit(testing.allocator);

    // Second commit (epoch 1 → 2) uses r1's outputs.
    // Multi-member group requires a path for the commit.
    const leaf_secret = [_]u8{0xF1} ** Default.nh;
    const eph_seeds = [_][32]u8{[_]u8{0xE1} ** 32};
    const new_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x63),
    );
    const new_leaf = makeTestLeaf(&new_enc.pk, &tg.sign_pk);

    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_leaf,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    const p2 = [_]Proposal{};

    var r2 = try createCommit(
        Default,
        testing.allocator,
        &r1.group_context,
        &r1.tree,
        tg.gs.my_leaf_index,
        &p2,
        &tg.sign_sk,
        &r1.interim_transcript_hash,
        &r1.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer r2.tree.deinit();
    defer r2.deinit(testing.allocator);

    // Transcript hashes should chain — r2's confirmed hash
    // should differ from r1's.
    try testing.expect(
        !std.mem.eql(
            u8,
            &r1.confirmed_transcript_hash,
            &r2.confirmed_transcript_hash,
        ),
    );
    try testing.expectEqual(@as(u64, 2), r2.new_epoch);
}

test "createCommit rejects invalid proposal list" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Self-remove should be rejected.
    const rm = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 0 } },
    };
    const proposals = [_]Proposal{rm};

    const result = createCommit(
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
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "createCommit commit_bytes encode valid Commit" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var eve_kp: TestKP = undefined;
    try eve_kp.init(0xE0, 0xE1, 0xE2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = eve_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var result = try createCommit(
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
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // The commit_bytes should be decodable as a Commit.
    const data = result.commit_bytes[0..result.commit_len];
    var dec_r = try Commit.decode(alloc, data, 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.proposals.len,
    );
    try testing.expect(dec_r.value.path == null);
}

test "processCommit round-trip with createCommit" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    // Creator creates the commit.
    var cr = try createCommit(
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

    // Receiver builds the FramedContent that the creator sent.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    // Receiver processes the commit.
    var pr = try processCommit(
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
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Both sides should agree on the new epoch.
    try testing.expectEqual(cr.new_epoch, pr.new_epoch);

    // Both sides should agree on epoch secrets.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.init_secret,
        &pr.epoch_secrets.init_secret,
    );

    // Both sides should agree on confirmed transcript hash.
    try testing.expectEqualSlices(
        u8,
        &cr.confirmed_transcript_hash,
        &pr.confirmed_transcript_hash,
    );

    // Both sides should agree on interim transcript hash.
    try testing.expectEqualSlices(
        u8,
        &cr.interim_transcript_hash,
        &pr.interim_transcript_hash,
    );

    // Tree should have 2 leaves on both sides.
    try testing.expectEqual(
        cr.tree.leaf_count,
        pr.tree.leaf_count,
    );
}

test "processCommit rejects wrong epoch" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    const proposals = [_]Proposal{};

    var cr = try createCommit(
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

    // Build FramedContent with WRONG epoch.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = 999,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    const result = processCommit(
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
    try testing.expectError(error.WrongEpoch, result);
}

test "processCommit rejects invalid confirmation tag" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    // Creator creates the commit.
    var cr = try createCommit(
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

    // Tamper with the confirmation tag.
    var bad_tag = cr.confirmation_tag;
    bad_tag[0] ^= 0xFF;

    const result = processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &bad_tag,
            .proposals = &proposals,
            .sender_verify_key = &tg.sign_pk,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );
    try testing.expectError(
        error.ConfirmationTagMismatch,
        result,
    );
}

test "processCommit rejects wrong signature key" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    const proposals = [_]Proposal{};

    var cr = try createCommit(
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

    // Use a different key for verification.
    const wrong_seed = [_]u8{0x99} ** 32;
    const wrong_kp = try Default.signKeypairFromSeed(
        &wrong_seed,
    );

    const result = processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &proposals,
            .sender_verify_key = &wrong_kp.pk,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
}

test "processCommit rejects non-member sender" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    const proposals = [_]Proposal{};

    var cr = try createCommit(
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

    // Build FramedContent with external sender type.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.external(0),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    const result = processCommit(
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
    try testing.expectError(error.NotAMember, result);
}

test "processCommit two-epoch chain matches createCommit" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // --- Epoch 0 → 1: Add bob ---
    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const p1 = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    }};

    var cr1 = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &p1,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(testing.allocator);

    const fc1 = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr1.commit_bytes[0..cr1.commit_len],
    };

    var pr1 = try processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc1,
            .signature = &cr1.signature,
            .confirmation_tag = &cr1.confirmation_tag,
            .proposals = &p1,
            .sender_verify_key = &tg.sign_pk,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );
    defer pr1.tree.deinit();
    defer pr1.deinit(testing.allocator);

    // --- Epoch 1 → 2: Add carol (add-only, no path needed) ---
    var carol_kp: TestKP = undefined;
    try carol_kp.init(0xC0, 0xC1, 0xC2);
    const p2 = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = carol_kp.kp,
            },
        },
    }};

    var cr2 = try createCommit(
        Default,
        testing.allocator,
        &cr1.group_context,
        &cr1.tree,
        tg.gs.my_leaf_index,
        &p2,
        &tg.sign_sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(testing.allocator);

    const fc2 = FramedContent{
        .group_id = pr1.group_context.group_id,
        .epoch = pr1.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr2.commit_bytes[0..cr2.commit_len],
    };

    var pr2 = try processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc2,
            .signature = &cr2.signature,
            .confirmation_tag = &cr2.confirmation_tag,
            .proposals = &p2,
            .sender_verify_key = &tg.sign_pk,
        },
        &pr1.group_context,
        &pr1.tree,
        &pr1.interim_transcript_hash,
        &pr1.epoch_secrets.init_secret,
    );
    defer pr2.tree.deinit();
    defer pr2.deinit(testing.allocator);

    // Both sides should agree at epoch 2.
    try testing.expectEqual(@as(u64, 2), cr2.new_epoch);
    try testing.expectEqual(@as(u64, 2), pr2.new_epoch);

    try testing.expectEqualSlices(
        u8,
        &cr2.epoch_secrets.epoch_secret,
        &pr2.epoch_secrets.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &cr2.confirmed_transcript_hash,
        &pr2.confirmed_transcript_hash,
    );
}

test "createCommit with path for empty commit" {
    const alloc = testing.allocator;

    // Generate real DH and signing keys.
    const alice_enc_kp = try Default.dhKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0xA2),
    );

    // Create group with Alice using real keys.
    const alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );

    var gs = try createGroup(
        Default,
        alloc,
        "path-test-group",
        alice_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob (Add-only commit, no path needed).
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB1, 0xB3, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const add_proposals = [_]Proposal{add_prop};

    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Verify Bob was added.
    try testing.expectEqual(@as(u32, 2), add_cr.tree.leaf_count);

    // Now make sure Bob's leaf has a real encryption key
    // so path can encrypt to it.
    const bob_check = try add_cr.tree.getLeaf(
        LeafIndex.fromU32(1),
    );
    try testing.expect(bob_check != null);

    // Empty commit with path — requires path because empty.
    // 2-leaf tree: leaf 0=alice, leaf 2=bob (node indices).
    // direct path of leaf 0 = [1] (root only).
    // copath of leaf 0 = [2] (bob's leaf node).
    // resolution(2) = {2} (bob is present).
    // So we need 1 eph seed.
    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
    };

    // New alice leaf node for commit source.
    const new_alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );

    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_alice_leaf,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    const empty_proposals = [_]Proposal{};

    var path_cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &empty_proposals,
        &alice_kp.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer path_cr.tree.deinit();
    defer path_cr.deinit(testing.allocator);

    // Epoch should advance.
    try testing.expectEqual(@as(u64, 2), path_cr.new_epoch);

    // Commit bytes should decode to a Commit with path.
    const data = path_cr.commit_bytes[0..path_cr.commit_len];
    var dec_r = try Commit.decode(alloc, data, 0);
    defer dec_r.value.deinit(alloc);

    try testing.expect(dec_r.value.path != null);
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.proposals.len,
    );

    // Confirmation tag should be non-zero.
    const zero = [_]u8{0} ** Default.nh;
    try testing.expect(
        !std.mem.eql(u8, &zero, &path_cr.confirmation_tag),
    );

    // Empty commit without path on multi-member group must fail.
    const no_path_result = createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &empty_proposals,
        &alice_kp.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(
        error.MissingPath,
        no_path_result,
    );
}

test "createCommit add-only does not include path" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var zara_kp: TestKP = undefined;
    try zara_kp.init(0x10, 0x11, 0x12);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = zara_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var result = try createCommit(
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
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // Decode commit — should have no path.
    const data = result.commit_bytes[0..result.commit_len];
    var dec_r = try Commit.decode(alloc, data, 0);
    defer dec_r.value.deinit(alloc);

    try testing.expect(dec_r.value.path == null);
    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.proposals.len,
    );
}

test "isPathRequired returns correct values" {
    // Empty commit → path required.
    var v: ValidatedProposals = undefined;
    v.gce = null;
    v.reinit = null;
    v.external_init = null;
    v.updates_len = 0;
    v.removes_len = 0;
    v.adds_len = 0;
    v.psk_ids_len = 0;
    try testing.expect(isPathRequired(&v));

    // Add-only → no path required.
    v.adds_len = 1;
    try testing.expect(!isPathRequired(&v));

    // Update → path required.
    v.adds_len = 0;
    v.updates_len = 1;
    try testing.expect(isPathRequired(&v));

    // Remove → path required.
    v.updates_len = 0;
    v.removes_len = 1;
    try testing.expect(isPathRequired(&v));

    // PSK-only → no path required.
    v.removes_len = 0;
    v.psk_ids_len = 1;
    try testing.expect(!isPathRequired(&v));

    // GCE → path required.
    v.psk_ids_len = 0;
    v.gce = .{ .extensions = &.{} };
    try testing.expect(isPathRequired(&v));
}

test "processCommit with path decryption round-trip" {
    const alloc = testing.allocator;

    // Alice and Bob real keys.
    const alice_enc_kp = try Default.dhKeypairFromSeed(
        &testSeed(0xC1),
    );
    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0xC2),
    );

    // Create group with Alice.
    const alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );

    var gs = try createGroup(
        Default,
        alloc,
        "process-path-test",
        alice_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob via Add-only commit (no path needed).
    // enc_tag=0xD1, init_tag=0xD3, sign_tag=0xD2
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xD1, 0xD3, 0xD2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const add_proposals = [_]Proposal{add_prop};

    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Now Alice creates an empty commit with path.
    // 2-leaf tree: direct path of leaf 0 = [root].
    // copath of leaf 0 = [leaf 2 (bob)].
    // resolution(bob's leaf) = {bob} → need 1 eph seed.
    const leaf_secret = [_]u8{0xF5} ** Default.nh;
    const eph_seeds = [_][32]u8{
        [_]u8{0xE5} ** 32,
    };

    // New leaf must use a FRESH encryption key (RFC S12.4.2).
    const new_alice_enc_kp = try Default.dhKeypairFromSeed(
        &testSeed(0xC3),
    );
    const new_alice_leaf = makeTestLeafWithPk(
        "alice",
        &new_alice_enc_kp.pk,
        &alice_kp.pk,
    );

    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_alice_leaf,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    const empty_proposals = [_]Proposal{};

    var path_cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &empty_proposals,
        &alice_kp.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer path_cr.tree.deinit();
    defer path_cr.deinit(testing.allocator);

    // Decode the Commit to get the UpdatePath.
    const commit_data = path_cr.commit_bytes[0..path_cr.commit_len];
    var dec = try Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    try testing.expect(dec.value.path != null);

    // Bob builds FramedContent and processes the commit.
    const fc = FramedContent{
        .group_id = add_cr.group_context.group_id,
        .epoch = add_cr.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    const rp: ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(1), // bob
        .receiver_sk = &bob_tkp.enc_sk,
        .receiver_pk = &bob_tkp.enc_pk,
    };

    var pr = try processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &path_cr.signature,
            .confirmation_tag = &path_cr.confirmation_tag,
            .proposals = &empty_proposals,
            .update_path = if (dec.value.path) |*p| p else null,
            .sender_verify_key = &alice_kp.pk,
            .receiver_params = rp,
        },
        &add_cr.group_context,
        &add_cr.tree,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Both sides should agree on the new epoch.
    try testing.expectEqual(path_cr.new_epoch, pr.new_epoch);

    // Both should agree on epoch secrets.
    try testing.expectEqualSlices(
        u8,
        &path_cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );

    // Both should agree on init_secret.
    try testing.expectEqualSlices(
        u8,
        &path_cr.epoch_secrets.init_secret,
        &pr.epoch_secrets.init_secret,
    );

    // Both should agree on confirmation key.
    try testing.expectEqualSlices(
        u8,
        &path_cr.epoch_secrets.confirmation_key,
        &pr.epoch_secrets.confirmation_key,
    );
}

test "processCommit rejects empty commit without path" {
    const alloc = testing.allocator;

    // Multi-member group: empty commit without path must fail.
    // createCommit rejects null path_params for multi-member
    // groups, so we verify that directly.
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Add Bob to make it a 2-member group.
    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB1, 0xB3, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    };
    const add_proposals = [_]Proposal{add_prop};

    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &add_proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Empty commit on multi-member group without path must fail.
    const empty_proposals = [_]Proposal{};
    const result = createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        tg.gs.my_leaf_index,
        &empty_proposals,
        &tg.sign_sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(error.MissingPath, result);
}

// ── KeyPackage validation tests (Section 10.1) ─────────────

test "createCommit rejects Add with mismatched cipher suite" {
    var tg: TestGroup = undefined;
    try tg.init(testing.allocator);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    // Override cipher suite to a different value.
    bob_kp.kp.cipher_suite =
        .mls_128_dhkemp256_aes128gcm_sha256_p256;
    bob_kp.kp.leaf_node.signature = &bob_kp.sig_buf;

    const proposals = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    }};

    const result = createCommit(
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
    try testing.expectError(
        error.CipherSuiteMismatch,
        result,
    );
}

test "createCommit rejects Add with mismatched version" {
    var tg: TestGroup = undefined;
    try tg.init(testing.allocator);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    // Override version to reserved value.
    bob_kp.kp.version = .reserved;

    const proposals = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    }};

    const result = createCommit(
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
    try testing.expectError(error.VersionMismatch, result);
}

test "createCommit rejects Add where init_key == enc_key" {
    var tg: TestGroup = undefined;
    try tg.init(testing.allocator);
    defer tg.deinit();

    // Use the same tag for enc and init → same key.
    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB0, 0xB2);

    const proposals = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    }};

    const result = createCommit(
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
    try testing.expectError(
        error.InvalidKeyPackage,
        result,
    );
}

test "createCommit with external PSK produces non-zero psk_secret" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Set up external PSK store with a known secret.
    var psk_store = psk_lookup_mod.InMemoryPskStore.init();
    const psk_secret = [_]u8{0xAA} ** 32;
    _ = psk_store.addPsk("test-psk", &psk_secret);

    var res_ring = psk_lookup_mod.ResumptionPskRing(
        Default,
    ).init(0);
    const resolver: PskResolver(Default) = .{
        .external = psk_store.lookup(),
        .resumption = &res_ring,
    };

    // PSK proposal referencing the stored external PSK.
    const psk_prop = Proposal{
        .tag = .psk,
        .payload = .{ .psk = .{ .psk = .{
            .psk_type = .external,
            .external_psk_id = "test-psk",
            .resumption_usage = .reserved,
            .resumption_group_id = "",
            .resumption_epoch = 0,
            .psk_nonce = &([_]u8{0x01} ** 32),
        } } },
    };
    const proposals = [_]Proposal{psk_prop};

    // Commit with PSK resolver.
    var cr_psk = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null, // PSK-only: no path needed
        resolver,
        .mls_public_message,
    );
    defer cr_psk.tree.deinit();
    defer cr_psk.deinit(testing.allocator);

    // ProcessCommit with same resolver must agree.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr_psk.commit_bytes[0..cr_psk.commit_len],
    };
    var pr = try processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr_psk.signature,
            .confirmation_tag = &cr_psk.confirmation_tag,
            .proposals = &proposals,
            .sender_verify_key = &tg.sign_pk,
            .psk_resolver = resolver,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    try testing.expectEqualSlices(
        u8,
        &cr_psk.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

test "createCommit with resumption PSK from prior epoch" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Retain epoch 0 resumption secret in the ring.
    var res_ring = psk_lookup_mod.ResumptionPskRing(
        Default,
    ).init(8);
    res_ring.retain(
        tg.gs.group_context.epoch,
        &tg.gs.epoch_secrets.resumption_psk,
    );

    var psk_store = psk_lookup_mod.InMemoryPskStore.init();
    const resolver: PskResolver(Default) = .{
        .external = psk_store.lookup(),
        .resumption = &res_ring,
    };

    // PSK proposal referencing epoch 0 resumption.
    const psk_prop = Proposal{
        .tag = .psk,
        .payload = .{ .psk = .{ .psk = .{
            .psk_type = .resumption,
            .external_psk_id = "",
            .resumption_usage = .application,
            .resumption_group_id = tg.gs.group_context.group_id,
            .resumption_epoch = 0,
            .psk_nonce = &([_]u8{0x02} ** 32),
        } } },
    };
    const proposals = [_]Proposal{psk_prop};

    var cr = try createCommit(
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
        resolver,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // ProcessCommit with same resolver must agree.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };
    var pr = try processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &proposals,
            .sender_verify_key = &tg.sign_pk,
            .psk_resolver = resolver,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

test "processCommit accepts valid membership tag" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_kp.kp } },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
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

    // Compute a valid membership tag.
    const mkey = &tg.gs.epoch_secrets.membership_key;
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = tg.gs.group_context.serialize(
        &gc_buf,
        // Safe: max_gc_encode is sized for max GroupContext.
    ) catch unreachable;
    const auth = auth_mod.FramedContentAuthData(Default){
        .signature = cr.signature,
        .confirmation_tag = cr.confirmation_tag,
    };
    const mtag = try public_msg.computeMembershipTag(
        Default,
        mkey,
        &fc,
        &auth,
        gc_bytes,
    );

    var pr = try processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &proposals,
            .sender_verify_key = &tg.sign_pk,
            .membership_key = mkey,
            .membership_tag = &mtag,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    try testing.expectEqual(cr.new_epoch, pr.new_epoch);
}

test "processCommit rejects wrong membership tag" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_kp.kp } },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
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

    // Compute a valid tag then corrupt it.
    const mkey = &tg.gs.epoch_secrets.membership_key;
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = tg.gs.group_context.serialize(
        &gc_buf,
        // Safe: max_gc_encode is sized for max GroupContext.
    ) catch unreachable;
    const auth = auth_mod.FramedContentAuthData(Default){
        .signature = cr.signature,
        .confirmation_tag = cr.confirmation_tag,
    };
    var mtag = try public_msg.computeMembershipTag(
        Default,
        mkey,
        &fc,
        &auth,
        gc_bytes,
    );
    mtag[0] ^= 0xFF;

    const result = processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &proposals,
            .sender_verify_key = &tg.sign_pk,
            .membership_key = mkey,
            .membership_tag = &mtag,
        },
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
    );
    try testing.expectError(
        error.MembershipTagMismatch,
        result,
    );
}

// ── UpdatePath validation tests (Phase 30.1) ─────────────────

/// Shared setup: Alice+Bob group, Alice creates empty commit
/// with path. Returns state for tampering the decoded path.
const PathTestCtx = struct {
    gs: GroupState(Default),
    add_cr: CommitResult(Default),
    path_cr: CommitResult(Default),
    path_commit: Commit,
    alice_sign: struct {
        sk: [Default.sign_sk_len]u8,
        pk: [Default.sign_pk_len]u8,
    },
    bob_tkp: TestKP,

    fn deinit(self: *PathTestCtx) void {
        self.path_commit.deinit(testing.allocator);
        self.path_cr.tree.deinit();
        self.path_cr.deinit(testing.allocator);
        self.add_cr.tree.deinit();
        self.add_cr.deinit(testing.allocator);
        self.gs.deinit();
        self.* = undefined;
    }

    fn init(self: *PathTestCtx) !void {
        const alloc = testing.allocator;
        const enc = try Default.dhKeypairFromSeed(
            &testSeed(0xC1),
        );
        const sign = try Default.signKeypairFromSeed(
            &testSeed(0xC2),
        );
        self.alice_sign = .{ .sk = sign.sk, .pk = sign.pk };
        self.gs = try createGroup(
            Default,
            alloc,
            "path-val-test",
            makeTestLeafWithPk(
                "alice",
                &enc.pk,
                &self.alice_sign.pk,
            ),
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            &.{},
        );
        try self.bob_tkp.init(0xD1, 0xD3, 0xD2);
        const add = [_]Proposal{.{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = self.bob_tkp.kp,
                },
            },
        }};
        self.add_cr = try createCommit(
            Default,
            testing.allocator,
            &self.gs.group_context,
            &self.gs.tree,
            self.gs.my_leaf_index,
            &add,
            &self.alice_sign.sk,
            &self.gs.interim_transcript_hash,
            &self.gs.epoch_secrets.init_secret,
            null,
            null,
            .mls_public_message,
        );
        try self.initPathCommit(alloc);
    }

    fn initPathCommit(self: *PathTestCtx, alloc: std.mem.Allocator) !void {
        const new_enc = try Default.dhKeypairFromSeed(
            &testSeed(0xC3),
        );
        const ls = [_]u8{0xF5} ** Default.nh;
        const es = [_][32]u8{[_]u8{0xE5} ** 32};
        const pp: PathParams(Default) = .{
            .allocator = alloc,
            .new_leaf = makeTestLeafWithPk(
                "alice",
                &new_enc.pk,
                &self.alice_sign.pk,
            ),
            .leaf_secret = &ls,
            .eph_seeds = &es,
        };
        const empty = [_]Proposal{};
        self.path_cr = try createCommit(
            Default,
            testing.allocator,
            &self.add_cr.group_context,
            &self.add_cr.tree,
            self.gs.my_leaf_index,
            &empty,
            &self.alice_sign.sk,
            &self.add_cr.interim_transcript_hash,
            &self.add_cr.epoch_secrets.init_secret,
            pp,
            null,
            .mls_public_message,
        );
        const data =
            self.path_cr.commit_bytes[0..self.path_cr.commit_len];
        const dec = try Commit.decode(alloc, data, 0);
        self.path_commit = dec.value;
    }

    /// Call processCommit on the path_commit. Caller can
    /// tamper with `self.path_commit.path` before calling.
    fn process(
        self: *PathTestCtx,
    ) CommitError!ProcessResult(Default) {
        const empty = [_]Proposal{};
        const data =
            self.path_cr.commit_bytes[0..self.path_cr.commit_len];
        const fc = FramedContent{
            .group_id = self.add_cr.group_context.group_id,
            .epoch = self.add_cr.group_context.epoch,
            .sender = Sender.member(self.gs.my_leaf_index),
            .authenticated_data = "",
            .content_type = .commit,
            .content = data,
        };
        const rp: ReceiverPathParams(Default) = .{
            .receiver = LeafIndex.fromU32(1),
            .receiver_sk = &self.bob_tkp.enc_sk,
            .receiver_pk = &self.bob_tkp.enc_pk,
        };
        return processCommit(
            Default,
            testing.allocator,
            .{
                .fc = &fc,
                .signature = &self.path_cr.signature,
                .confirmation_tag = &self.path_cr.confirmation_tag,
                .proposals = &empty,
                .update_path = if (self.path_commit.path) |*p| p else null,
                .sender_verify_key = &self.alice_sign.pk,
                .receiver_params = rp,
            },
            &self.add_cr.group_context,
            &self.add_cr.tree,
            &self.add_cr.interim_transcript_hash,
            &self.add_cr.epoch_secrets.init_secret,
        );
    }
};

test "processCommit rejects non-commit leaf source" {
    var context: PathTestCtx = undefined;
    try context.init();
    defer context.deinit();

    context.path_commit.path.?.leaf_node.source = .key_package;

    const result = context.process();
    try testing.expectError(error.InvalidLeafNode, result);
}

test "processCommit rejects reused leaf encryption_key" {
    var context: PathTestCtx = undefined;
    try context.init();
    defer context.deinit();

    // Overwrite path leaf encryption_key bytes with Alice's
    // current key so the freshness check fires.
    const index =
        context.gs.my_leaf_index.toNodeIndex().toUsize();
    const old_ek =
        context.add_cr.tree.nodes[index].?.payload.leaf
            .encryption_key;
    const dst = @constCast(
        context.path_commit.path.?.leaf_node.encryption_key,
    );
    @memcpy(dst, old_ek);

    const result = context.process();
    try testing.expectError(error.InvalidLeafNode, result);
}

test "processCommit rejects duplicate path node key" {
    var context: PathTestCtx = undefined;
    try context.init();
    defer context.deinit();

    // Overwrite path node key bytes with Bob's leaf key.
    const bob_idx =
        LeafIndex.fromU32(1).toNodeIndex().toUsize();
    const bob_ek =
        context.add_cr.tree.nodes[bob_idx].?.payload.leaf
            .encryption_key;
    if (context.path_commit.path) |*p| {
        if (p.nodes.len > 0) {
            const dst = @constCast(p.nodes)[0]
                .encryption_key;
            @memcpy(@constCast(dst), bob_ek);
        }
    }

    const result = context.process();
    try testing.expectError(error.InvalidLeafNode, result);
}

test "verifyParentHashes rejects tampered parent hash" {
    // Build a 2-leaf tree with a valid commit path, then
    // tamper the leaf's parent_hash. verifyParentHashes must
    // detect the mismatch.
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xB1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xB2),
    );
    const bob_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xB3),
    );
    const bob_sig = try Default.signKeypairFromSeed(
        &testSeed(0xB4),
    );

    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    // Set two leaves. Alice = commit source with parent_hash.
    var alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc.pk,
        &alice_sig.pk,
    );
    alice_leaf.source = .commit;

    try tree.setLeaf(LeafIndex.fromU32(1), makeTestLeafWithPk(
        "bob",
        &bob_enc.pk,
        &bob_sig.pk,
    ));

    // Set root parent node with a known key.
    const root_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xB5),
    );
    try tree.setNode(
        NodeIndex.fromU32(1),
        node_mod.Node.initParent(.{
            .encryption_key = &root_enc.pk,
            .parent_hash = "",
            .unmerged_leaves = &.{},
        }),
    );

    // Compute correct parent_hash for Alice's leaf.
    var ph_buf: [Default.nh]u8 = undefined;
    if (try path_mod.computeLeafParentHash(
        Default,
        testing.allocator,
        &tree,
        LeafIndex.fromU32(0),
    )) |ph| {
        ph_buf = ph;
        alice_leaf.parent_hash = &ph_buf;
    }
    try tree.setLeaf(LeafIndex.fromU32(0), alice_leaf);

    // Valid tree should pass.
    _ = try tree_hashes.verifyParentHashes(Default, testing.allocator, &tree);

    // Tamper the parent_hash on Alice's leaf in the tree.
    const leaf_slot = &tree.nodes[0];
    const leaf_ptr = &leaf_slot.*.?.payload.leaf;
    if (leaf_ptr.parent_hash) |ph| {
        @constCast(ph)[0] ^= 0xFF;
    }

    // Now verification must fail.
    const result = tree_hashes.verifyParentHashes(Default, testing.allocator, &tree);
    try testing.expectError(error.ParentHashMismatch, result);
}

test "processCommit rejects GCE commit without path" {
    // ProcessCommit must reject a commit with a GCE proposal
    // but no UpdatePath, since path is required per RFC 12.4.
    const alloc = testing.allocator;
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xE1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xE2),
    );
    var gs = try createGroup(
        Default,
        alloc,
        "gce-no-path",
        makeTestLeafWithPk(
            "alice",
            &alice_enc.pk,
            &alice_sig.pk,
        ),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob so path derivation succeeds.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xE5, 0xE6, 0xE7);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_tkp.kp } },
    };
    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &[_]Proposal{add_prop},
        &alice_sig.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Create a GCE commit with a path (valid for createCommit).
    const gce_prop = Proposal{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{ .extensions = &.{} },
        },
    };
    const new_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xE8),
    );
    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = makeTestLeafWithPk(
            "alice",
            &new_enc.pk,
            &alice_sig.pk,
        ),
        .leaf_secret = &([_]u8{0xE9} ** Default.nh),
        .eph_seeds = &[_][32]u8{[_]u8{0xEA} ** 32},
    };
    var cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &[_]Proposal{gce_prop},
        &alice_sig.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Bob processes — pass null UpdatePath to simulate missing.
    const data = cr.commit_bytes[0..cr.commit_len];
    const fc = FramedContent{
        .group_id = add_cr.group_context.group_id,
        .epoch = add_cr.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = data,
    };
    const result = processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &[_]Proposal{gce_prop},
            .sender_verify_key = &alice_sig.pk,
        },
        &add_cr.group_context,
        &add_cr.tree,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
    );
    try testing.expectError(error.MissingPath, result);
}

test "processCommit accepts GCE commit with path" {
    // Companion to the rejection test above: a GCE commit WITH
    // a valid UpdatePath must be accepted by processCommit.
    const alloc = testing.allocator;
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xF1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xF2),
    );
    var gs = try createGroup(
        Default,
        alloc,
        "gce-path-ok",
        makeTestLeafWithPk(
            "alice",
            &alice_enc.pk,
            &alice_sig.pk,
        ),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob so path derivation works.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xF3, 0xF4, 0xF5);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_tkp.kp } },
    };
    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &[_]Proposal{add_prop},
        &alice_sig.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Alice creates GCE commit with path.
    const gce_prop = Proposal{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{ .extensions = &.{} },
        },
    };
    const new_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xF6),
    );
    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = makeTestLeafWithPk(
            "alice",
            &new_enc.pk,
            &alice_sig.pk,
        ),
        .leaf_secret = &([_]u8{0xF7} ** Default.nh),
        .eph_seeds = &[_][32]u8{[_]u8{0xF8} ** 32},
    };

    var cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &[_]Proposal{gce_prop},
        &alice_sig.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Decode commit to get UpdatePath.
    const commit_data = cr.commit_bytes[0..cr.commit_len];
    var dec = try Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);
    try testing.expect(dec.value.path != null);

    // Bob processes commit WITH path — should succeed.
    const fc = FramedContent{
        .group_id = add_cr.group_context.group_id,
        .epoch = add_cr.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };
    const rp: ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(1),
        .receiver_sk = &bob_tkp.enc_sk,
        .receiver_pk = &bob_tkp.enc_pk,
    };
    var pr = try processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &[_]Proposal{gce_prop},
            .update_path = if (dec.value.path) |*p| p else null,
            .sender_verify_key = &alice_sig.pk,
            .receiver_params = rp,
        },
        &add_cr.group_context,
        &add_cr.tree,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Both sides agree on epoch secrets.
    try testing.expectEqual(cr.new_epoch, pr.new_epoch);
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

test "processCommit with mls_private_message wire format" {
    // Verify that a commit created with mls_private_message wire
    // format is correctly processed when the receiver also uses
    // mls_private_message. This exercises the wire_format field
    // in FramedContentTBS (RFC 9420 S6.1).
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xA2),
    );
    var gs = try createGroup(
        Default,
        alloc,
        "priv-commit",
        makeTestLeafWithPk(
            "alice",
            &alice_enc.pk,
            &alice_sig.pk,
        ),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xA3, 0xA4, 0xA5);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_tkp.kp } },
    };
    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &[_]Proposal{add_prop},
        &alice_sig.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Alice creates empty commit with mls_private_message.
    const new_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA6),
    );
    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = makeTestLeafWithPk(
            "alice",
            &new_enc.pk,
            &alice_sig.pk,
        ),
        .leaf_secret = &([_]u8{0xA7} ** Default.nh),
        .eph_seeds = &[_][32]u8{[_]u8{0xA8} ** 32},
    };

    var cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &[_]Proposal{},
        &alice_sig.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_private_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Bob processes with mls_private_message wire format.
    const commit_data = cr.commit_bytes[0..cr.commit_len];
    var dec = try Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    const fc = FramedContent{
        .group_id = add_cr.group_context.group_id,
        .epoch = add_cr.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    const rp: ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(1),
        .receiver_sk = &bob_tkp.enc_sk,
        .receiver_pk = &bob_tkp.enc_pk,
    };

    var pr = try processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &[_]Proposal{},
            .update_path = if (dec.value.path) |*p| p else null,
            .sender_verify_key = &alice_sig.pk,
            .receiver_params = rp,
            .wire_format = .mls_private_message,
        },
        &add_cr.group_context,
        &add_cr.tree,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Both agree on epoch secrets.
    try testing.expectEqual(cr.new_epoch, pr.new_epoch);
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

test "epochAuthenticator changes across epochs" {
    // After createCommit advances the epoch, the
    // epoch_authenticator derived in EpochSecrets must differ
    // from the previous epoch.
    const alloc = testing.allocator;
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xB1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xB2),
    );
    var gs = try createGroup(
        Default,
        alloc,
        "ea-test",
        makeTestLeafWithPk(
            "alice",
            &alice_enc.pk,
            &alice_sig.pk,
        ),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    const ea0 = gs.epoch_secrets.epoch_authenticator;

    // Add Bob and advance epoch.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB3, 0xB4, 0xB5);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_tkp.kp } },
    };
    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &[_]Proposal{add_prop},
        &alice_sig.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    const ea1 = cr.epoch_secrets.epoch_authenticator;

    // Must differ.
    try testing.expect(!std.mem.eql(u8, &ea0, &ea1));
}
