// Integration tests for the zmls MLS library.
//
// These tests exercise end-to-end protocol flows across
// multiple modules: group creation, commit, welcome,
// external join, and application messaging.

const std = @import("std");
const testing = std.testing;
const mls = @import("zmls");

const Default = mls.DefaultCryptoProvider;
const Credential = mls.Credential;
const LeafNode = mls.LeafNode;
const LeafIndex = mls.LeafIndex;
const Proposal = mls.Proposal;
const FramedContent = mls.FramedContent;
const Sender = mls.Sender;
const GroupContext = mls.GroupContext;
const Extension = mls.Extension;

const primitives = mls.crypto_primitives;
const schedule = mls.key_schedule;
const secret_tree_mod = mls.secret_tree;
const KeyPackage = mls.key_package.KeyPackage;

const ProtocolVersion = mls.ProtocolVersion;
const CipherSuite = mls.CipherSuite;

const max_gc_encode = mls.group_context.max_gc_encode;

// ── Helpers ─────────────────────────────────────────────────

/// Deterministic seed derivation from a u8 tag.
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
    const ext_types = comptime [_]mls.ExtensionType{};
    const prop_types = comptime [_]mls.types.ProposalType{};
    const cred_types = comptime [_]mls.types.CredentialType{
        .basic,
    };

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

const suite: CipherSuite =
    .mls_128_dhkemx25519_aes128gcm_sha256_ed25519;

// ── Test 1: Full lifecycle ──────────────────────────────────
//
// Create group → add member via commit+welcome → both agree
// on epoch secrets.

test "full lifecycle: create → add → welcome → join" {
    const alloc = testing.allocator;

    // Alice key pairs.
    const alice_enc_kp = try Default.dhKeypairFromSeed(
        &([_]u8{0xA1} ** 32),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &([_]u8{0xA2} ** 32),
    );

    // 1. Alice creates the group.
    var gs = try mls.createGroup(
        Default,
        alloc,
        "lifecycle-test",
        makeTestLeafWithKeys(
            &alice_enc_kp.pk,
            &alice_sign.pk,
        ),
        suite,
        &.{},
    );
    defer gs.deinit();

    try testing.expectEqual(@as(u64, 0), gs.epoch());
    try testing.expectEqual(@as(u32, 1), gs.leafCount());

    // 2. Alice commits to add Bob.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB1, 0xB3, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try mls.createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 1), cr.new_epoch);
    try testing.expectEqual(@as(u32, 2), cr.tree.leaf_count);

    // 3. Build Welcome for Bob.
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    const eph_seed = [_]u8{0xCC} ** 32;
    const new_members = [_]mls.group_welcome.NewMemberEntry(Default){
        .{
            .kp_ref = &kp_ref,
            .init_pk = &bob_tkp.init_pk,
            .eph_seed = &eph_seed,
            .leaf_index = LeafIndex.fromU32(1),
        },
    };

    var wr = try mls.buildWelcome(
        Default,
        alloc,
        gc_bytes,
        &cr.confirmation_tag,
        &cr.epoch_secrets.welcome_secret,
        &cr.epoch_secrets.joiner_secret,
        &alice_sign.sk,
        0,
        suite,
        &new_members,
        &.{},
        null,
        0,
        null,
        0,
    );
    defer wr.deinit(alloc);

    // 4. Bob processes the Welcome.
    var bob_gs = try mls.processWelcome(
        Default,
        alloc,
        &wr.welcome,
        &kp_ref,
        &bob_tkp.init_sk,
        &bob_tkp.init_pk,
        &alice_sign.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        null,
    );
    defer bob_gs.deinit();

    // 5. Verify agreement.
    try testing.expectEqual(@as(u64, 1), bob_gs.epoch());
    try testing.expectEqual(@as(u32, 2), bob_gs.leafCount());

    // Epoch secrets match.
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
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.confirmation_key,
        &bob_gs.epoch_secrets.confirmation_key,
    );
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.encryption_secret,
        &bob_gs.epoch_secrets.encryption_secret,
    );
}

// ── Test 2: Three-party group ───────────────────────────────
//
// Create → add B → add C → all agree on final epoch.

test "three-party group: create → add B → add C" {
    const alloc = testing.allocator;

    // Alice keys.
    const alice_enc = try Default.dhKeypairFromSeed(
        &([_]u8{0x11} ** 32),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &([_]u8{0x12} ** 32),
    );

    // 1. Alice creates the group.
    var gs = try mls.createGroup(
        Default,
        alloc,
        "three-party",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // 2. Add Bob.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x21, 0x23, 0x22);

    const add_bob = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const p1 = [_]Proposal{add_bob};

    var cr1 = try mls.createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &p1,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 1), cr1.new_epoch);
    try testing.expectEqual(@as(u32, 2), cr1.tree.leaf_count);

    // 3. Add Carol (another commit on top of epoch 1).
    var carol_tkp: TestKP = undefined;
    try carol_tkp.init(0x31, 0x33, 0x32);

    const add_carol = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = carol_tkp.kp },
        },
    };
    const p2 = [_]Proposal{add_carol};

    var cr2 = try mls.createCommit(
        Default,
        testing.allocator,
        &cr1.group_context,
        &cr1.tree,
        gs.my_leaf_index,
        &p2,
        &alice_sign.sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 2), cr2.new_epoch);
    try testing.expectEqual(@as(u32, 3), cr2.tree.leaf_count);

    // 4. Bob processes both commits to reach epoch 2.
    // Bob processes commit 1.
    const fc1 = FramedContent{
        .group_id = gs.group_context.group_id,
        .epoch = gs.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr1.commit_bytes[0..cr1.commit_len],
    };

    var pr1 = try mls.processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc1,
            .signature = &cr1.signature,
            .confirmation_tag = &cr1.confirmation_tag,
            .proposals = &p1,
            .sender_verify_key = &alice_sign.pk,
        },
        &gs.group_context,
        &gs.tree,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
    );
    defer pr1.tree.deinit();
    defer pr1.deinit(testing.allocator);

    // Bob processes commit 2.
    const fc2 = FramedContent{
        .group_id = pr1.group_context.group_id,
        .epoch = pr1.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr2.commit_bytes[0..cr2.commit_len],
    };

    var pr2 = try mls.processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc2,
            .signature = &cr2.signature,
            .confirmation_tag = &cr2.confirmation_tag,
            .proposals = &p2,
            .sender_verify_key = &alice_sign.pk,
        },
        &pr1.group_context,
        &pr1.tree,
        &pr1.interim_transcript_hash,
        &pr1.epoch_secrets.init_secret,
    );
    defer pr2.tree.deinit();
    defer pr2.deinit(testing.allocator);

    // All agree: epoch 2, 3 leaves.
    try testing.expectEqual(@as(u64, 2), pr2.new_epoch);
    try testing.expectEqual(@as(u32, 3), pr2.tree.leaf_count);

    // Epoch secrets match.
    try testing.expectEqualSlices(
        u8,
        &cr2.epoch_secrets.epoch_secret,
        &pr2.epoch_secrets.epoch_secret,
    );
}

// ── Test 3: Member removal ──────────────────────────────────
//
// Create → add B → remove B → verify tree shrinks.

test "member removal: create → add 3 → remove" {
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &([_]u8{0x41} ** 32),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &([_]u8{0x42} ** 32),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "removal-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // Add Bob, Carol, Dave → 4-leaf balanced tree.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x51, 0x57, 0x52);
    var carol_tkp: TestKP = undefined;
    try carol_tkp.init(0x53, 0x58, 0x54);
    var dave_tkp: TestKP = undefined;
    try dave_tkp.init(0x55, 0x59, 0x56);

    const add_three = [_]Proposal{
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = bob_tkp.kp },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = carol_tkp.kp },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = dave_tkp.kp },
            },
        },
    };

    var cr1 = try mls.createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_three,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 4), cr1.tree.leaf_count);

    // Remove Bob (leaf index 1) from the 4-leaf tree.
    // 4-leaf tree (7 nodes):
    //        3
    //      /   \
    //     1     5
    //    / \   / \
    //   0   2 4   6
    //   A   B C   D
    //
    // Alice = leaf 0 (node 0). Direct path = [1, 3].
    // Copath = [node 2 (bob), node 5].
    // Bob (node 2) is removed → resolution({}) = 0 seeds.
    // Node 5: left=4(carol), right=6(dave). resolution =
    //   {carol, dave} → 2 eph seeds.
    // Total eph seeds = 0 + 2 = 2.
    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const eph_seeds = [_][32]u8{
        [_]u8{0xE0} ** 32,
        [_]u8{0xE1} ** 32,
    };

    // New leaf must use a FRESH encryption key (RFC S12.4.2).
    const new_alice_enc = try Default.dhKeypairFromSeed(
        &([_]u8{0x43} ** 32),
    );
    const new_alice = makeTestLeafWithKeys(
        &new_alice_enc.pk,
        &alice_sign.pk,
    );

    const rm_bob = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 1 } },
    };
    const rm_proposals = [_]Proposal{rm_bob};

    const pp: mls.PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_alice,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    var cr2 = try mls.createCommit(
        Default,
        testing.allocator,
        &cr1.group_context,
        &cr1.tree,
        gs.my_leaf_index,
        &rm_proposals,
        &alice_sign.sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 4), cr2.tree.leaf_count);
    try testing.expectEqual(@as(u64, 2), cr2.new_epoch);

    // Bob's leaf should be blank (removed).
    const bob_leaf = try cr2.tree.getLeaf(
        LeafIndex.fromU32(1),
    );
    try testing.expect(bob_leaf == null);

    // Alice, Carol, Dave still present.
    try testing.expect(
        (try cr2.tree.getLeaf(LeafIndex.fromU32(0))) != null,
    );
    try testing.expect(
        (try cr2.tree.getLeaf(LeafIndex.fromU32(2))) != null,
    );
    try testing.expect(
        (try cr2.tree.getLeaf(LeafIndex.fromU32(3))) != null,
    );

    // Carol can process the commit with path decryption.
    const commit_data =
        cr2.commit_bytes[0..cr2.commit_len];
    var dec = try mls.Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    try testing.expect(dec.value.path != null);

    const fc = FramedContent{
        .group_id = cr1.group_context.group_id,
        .epoch = cr1.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    const rp: mls.ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(2),
        .receiver_sk = &carol_tkp.enc_sk,
        .receiver_pk = &carol_tkp.enc_pk,
    };

    var pr = try mls.processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr2.signature,
            .confirmation_tag = &cr2.confirmation_tag,
            .proposals = &rm_proposals,
            .update_path = if (dec.value.path) |*p| p else null,
            .sender_verify_key = &alice_sign.pk,
            .receiver_params = rp,
        },
        &cr1.group_context,
        &cr1.tree,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Carol agrees on epoch and secrets.
    try testing.expectEqual(cr2.new_epoch, pr.new_epoch);
    try testing.expectEqualSlices(
        u8,
        &cr2.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );

    // Bob's leaf is blank on Carol's side too.
    const carol_bob = try pr.tree.getLeaf(
        LeafIndex.fromU32(1),
    );
    try testing.expect(carol_bob == null);
}

// ── Test 4: Key update with path ────────────────────────────
//
// Create → add B → empty commit with path → verify epoch
// secrets differ from no-path commit.

test "key update: empty commit with path changes secrets" {
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &([_]u8{0x61} ** 32),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &([_]u8{0x62} ** 32),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "key-update-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // Add Bob so the tree has 2 leaves.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x71, 0x73, 0x72);

    const add_bob = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    }};

    var cr1 = try mls.createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_bob,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(testing.allocator);

    // Empty commit with path.
    // 2-leaf tree, Alice at leaf 0:
    // Direct path = [root], copath = [bob's leaf].
    // resolution(bob) = {bob} → 1 eph seed.
    const leaf_secret = [_]u8{0xF1} ** Default.nh;
    const eph_seeds = [_][32]u8{[_]u8{0xE1} ** 32};
    // New leaf must use a FRESH encryption key (RFC S12.4.2).
    const new_alice_enc = try Default.dhKeypairFromSeed(
        &([_]u8{0x63} ** 32),
    );
    const new_alice = makeTestLeafWithKeys(
        &new_alice_enc.pk,
        &alice_sign.pk,
    );

    const pp: mls.PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_alice,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    const empty = [_]Proposal{};

    var cr_path = try mls.createCommit(
        Default,
        testing.allocator,
        &cr1.group_context,
        &cr1.tree,
        gs.my_leaf_index,
        &empty,
        &alice_sign.sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer cr_path.tree.deinit();
    defer cr_path.deinit(testing.allocator);

    // No-path empty commit must fail on a multi-member group.
    try testing.expectError(
        error.MissingPath,
        mls.createCommit(
            Default,
            testing.allocator,
            &cr1.group_context,
            &cr1.tree,
            gs.my_leaf_index,
            &empty,
            &alice_sign.sk,
            &cr1.interim_transcript_hash,
            &cr1.epoch_secrets.init_secret,
            null,
            null,
            .mls_public_message,
        ),
    );

    // Bob decrypts the path.
    const commit_data =
        cr_path.commit_bytes[0..cr_path.commit_len];
    var dec = try mls.Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    try testing.expect(dec.value.path != null);

    const fc = FramedContent{
        .group_id = cr1.group_context.group_id,
        .epoch = cr1.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    const rp: mls.ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(1),
        .receiver_sk = &bob_tkp.enc_sk,
        .receiver_pk = &bob_tkp.enc_pk,
    };

    var pr = try mls.processCommit(
        Default,
        testing.allocator,
        .{
            .fc = &fc,
            .signature = &cr_path.signature,
            .confirmation_tag = &cr_path.confirmation_tag,
            .proposals = &empty,
            .update_path = if (dec.value.path) |*p| p else null,
            .sender_verify_key = &alice_sign.pk,
            .receiver_params = rp,
        },
        &cr1.group_context,
        &cr1.tree,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Bob agrees with Alice on path-based secrets.
    try testing.expectEqualSlices(
        u8,
        &cr_path.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

// ── Test 5: External join ───────────────────────────────────
//
// Create group → derive external_pub → external commit →
// both sides agree.

test "external join: create → external commit → agree" {
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &([_]u8{0x81} ** 32),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &([_]u8{0x82} ** 32),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "ext-join-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // Build external_pub extension.
    var ext_pub_buf: [Default.npk]u8 = undefined;
    const ext_pub_ext = try mls.makeExternalPubExtension(
        Default,
        &gs.epoch_secrets.external_secret,
        &ext_pub_buf,
    );
    const gi_exts = [_]Extension{ext_pub_ext};

    // Bob joins via external commit.
    const bob_enc = try Default.dhKeypairFromSeed(
        &([_]u8{0x91} ** 32),
    );
    const bob_sign = try Default.signKeypairFromSeed(
        &([_]u8{0x92} ** 32),
    );

    const leaf_secret = [_]u8{0xF1} ** Default.nh;
    const ext_init_seed = [_]u8{0xF2} ** 32;
    const eph_seeds = [_][32]u8{[_]u8{0xE1} ** 32};

    var ec = try mls.createExternalCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        &gi_exts,
        &gs.interim_transcript_hash,
        .{
            .allocator = alloc,
            .joiner_leaf = makeTestLeafWithKeys(
                &bob_enc.pk,
                &bob_sign.pk,
            ),
            .sign_key = &bob_sign.sk,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
            .ext_init_seed = &ext_init_seed,
            .remove_proposals = &.{},
        },
        .mls_public_message,
    );
    defer ec.tree.deinit();
    defer ec.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 1), ec.new_epoch);
    try testing.expectEqual(@as(u32, 2), ec.tree.leaf_count);

    // Alice processes the external commit.
    const commit_data = ec.commit_bytes[0..ec.commit_len];
    var dec = try mls.Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    const por_list = dec.value.proposals;
    var prop_buf: [257]Proposal = undefined;
    const ext_proposals = try mls.resolveExternalInlineProposals(
        por_list,
        &prop_buf,
    );

    const fc = FramedContent{
        .group_id = gs.group_context.group_id,
        .epoch = gs.group_context.epoch,
        .sender = Sender.newMemberCommit(),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    var pr = try mls.processExternalCommit(
        Default,
        testing.allocator,
        &fc,
        &ec.signature,
        &ec.confirmation_tag,
        ext_proposals,
        &dec.value.path.?,
        &gs.group_context,
        &gs.tree,
        &bob_sign.pk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.external_secret,
        null,
        gs.my_leaf_index,
        &alice_enc.sk,
        &alice_enc.pk,
        .mls_public_message,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Both agree.
    try testing.expectEqual(ec.new_epoch, pr.new_epoch);
    try testing.expectEqualSlices(
        u8,
        &ec.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &ec.epoch_secrets.encryption_secret,
        &pr.epoch_secrets.encryption_secret,
    );
}

// ── Test 6: Multi-epoch chain ───────────────────────────────
//
// Create → commit epoch 1 → commit epoch 2 → commit epoch 3
// → verify each epoch advances correctly.

test "multi-epoch chain: 4 sequential commits" {
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &([_]u8{0xC1} ** 32),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &([_]u8{0xC2} ** 32),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "chain-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // Pre-create 3 signed KeyPackages (bob, carol, dave).
    var tkps: [3]TestKP = undefined;
    try tkps[0].init(0xD1, 0xD4, 0xD7);
    try tkps[1].init(0xD2, 0xD5, 0xD8);
    try tkps[2].init(0xD3, 0xD6, 0xD9);

    var prev_gc = gs.group_context;
    var prev_tree = gs.tree;
    var prev_ith = gs.interim_transcript_hash;
    var prev_init = gs.epoch_secrets.init_secret;

    // We'll chain through 3 adds.
    var trees: [3]mls.RatchetTree = undefined;
    var gcs: [3]mls.GroupContext(Default.nh) = undefined;
    var tree_count: u32 = 0;
    defer {
        var k: u32 = 0;
        while (k < tree_count) : (k += 1) {
            trees[k].deinit();
            gcs[k].deinit(testing.allocator);
        }
    }

    var last_epoch: u64 = 0;

    for (&tkps) |*tkp| {
        const p = [_]Proposal{.{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = tkp.kp },
            },
        }};

        const cr = try mls.createCommit(
            Default,
            testing.allocator,
            &prev_gc,
            &prev_tree,
            gs.my_leaf_index,
            &p,
            &alice_sign.sk,
            &prev_ith,
            &prev_init,
            null,
            null,
            .mls_public_message,
        );

        trees[tree_count] = cr.tree;
        gcs[tree_count] = cr.group_context;
        tree_count += 1;

        prev_gc = cr.group_context;
        prev_tree = cr.tree;
        prev_ith = cr.interim_transcript_hash;
        prev_init = cr.epoch_secrets.init_secret;
        last_epoch = cr.new_epoch;
    }

    // After 3 adds: epoch 3, 4 leaves.
    try testing.expectEqual(@as(u64, 3), last_epoch);
    try testing.expectEqual(@as(u32, 4), prev_tree.leaf_count);
}

// ── Test 7: Exporter ────────────────────────────────────────
//
// Verify that MLS exporter produces deterministic output.

test "exporter: deterministic secret export" {
    const secret = [_]u8{0xAA} ** Default.nh;
    var r1: [Default.nh]u8 = undefined;
    var r2: [Default.nh]u8 = undefined;
    mls.mlsExporter(
        Default,
        &secret,
        "test-label",
        "test-context",
        &r1,
    );
    mls.mlsExporter(
        Default,
        &secret,
        "test-label",
        "test-context",
        &r2,
    );

    try testing.expectEqualSlices(u8, &r1, &r2);

    // Different label → different output.
    var r3: [Default.nh]u8 = undefined;
    mls.mlsExporter(
        Default,
        &secret,
        "other-label",
        "test-context",
        &r3,
    );
    try testing.expect(!std.mem.eql(u8, &r1, &r3));
}

// ── Method-based API test (Phase 33.2) ──────────────────────

test "method API: createCommit + joinViaWelcome" {
    const alloc = testing.allocator;
    // 1. Alice creates a group (same setup as above).
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA2),
    );
    var alice_leaf = makeTestLeafWithKeys(
        &alice_enc.pk,
        &alice_sign.pk,
    );
    alice_leaf.source = .key_package;

    var gs = try mls.createGroup(
        Default,
        alloc,
        "method-api-group",
        alice_leaf,
        suite,
        &.{},
    );
    defer gs.deinit();

    // 2. Bob key package.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB1, 0xB3, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    // 3. Create commit via method API.
    var cr = try gs.createCommit(alloc, .{
        .proposals = &proposals,
        .sign_key = &alice_sign.sk,
    });
    defer cr.tree.deinit();
    defer cr.deinit(alloc);

    try testing.expectEqual(@as(u64, 1), cr.new_epoch);
    try testing.expectEqual(@as(u32, 2), cr.tree.leaf_count);

    // 4. Build Welcome via method API.
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );
    const eph_seed = [_]u8{0xCC} ** 32;
    const new_members = [_]mls.group_welcome.NewMemberEntry(Default){
        .{
            .kp_ref = &kp_ref,
            .init_pk = &bob_tkp.init_pk,
            .eph_seed = &eph_seed,
            .leaf_index = LeafIndex.fromU32(1),
        },
    };

    var wr = try gs.buildWelcome(alloc, .{
        .gc_bytes = gc_bytes,
        .confirmation_tag = &cr.confirmation_tag,
        .welcome_secret = &cr.epoch_secrets.welcome_secret,
        .joiner_secret = &cr.epoch_secrets.joiner_secret,
        .sign_key = &alice_sign.sk,
        .signer = 0,
        .cipher_suite = suite,
        .new_members = &new_members,
    });
    defer wr.deinit(alloc);

    // 5. Bob joins via Welcome using method API.
    const GS = mls.GroupState(Default);
    var bob_gs = try GS.joinViaWelcome(alloc, .{
        .welcome = &wr.welcome,
        .kp_ref = &kp_ref,
        .init_sk = &bob_tkp.init_sk,
        .init_pk = &bob_tkp.init_pk,
        .signer_verify_key = &alice_sign.pk,
        .tree_data = .{ .prebuilt = cr.tree },
        .my_leaf_index = LeafIndex.fromU32(1),
    });
    defer bob_gs.deinit();

    // 6. Verify agreement.
    try testing.expectEqual(@as(u64, 1), bob_gs.epoch());
    try testing.expectEqual(@as(u32, 2), bob_gs.leafCount());
    // Compare post-commit epoch authenticator (from the
    // CommitResult) with Bob's epoch authenticator.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_authenticator,
        bob_gs.epochAuthenticator(),
    );
}

// ── Test: PSK proposal end-to-end ───────────────────────────
//
// Create → add B → commit with external PSK → both agree.

test "PSK proposal: external PSK through commit pipeline" {
    const alloc = testing.allocator;

    // Alice creates a group.
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xA2),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "psk-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // Add Bob.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB1, 0xB3, 0xB2);

    const add_bob = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    }};

    var cr1 = try mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_bob,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(alloc);

    // Set up PSK store with a shared external PSK.
    const psk_id = "test-external-psk";
    const psk_secret = [_]u8{0xDE} ** Default.nh;
    const psk_nonce = [_]u8{0x01} ** Default.nh;
    var psk_store = mls.InMemoryPskStore.init();
    _ = psk_store.addPsk(psk_id, &psk_secret);

    var res_ring = mls.ResumptionPskRing(Default).init(0);

    const resolver: mls.PskResolver(Default) = .{
        .external = psk_store.lookup(),
        .resumption = &res_ring,
    };

    // PSK proposal (external).
    const psk_prop = Proposal{
        .tag = .psk,
        .payload = .{
            .psk = .{
                .psk = .{
                    .psk_type = .external,
                    .external_psk_id = psk_id,
                    .psk_nonce = &psk_nonce,
                    .resumption_usage = .application,
                    .resumption_group_id = &.{},
                    .resumption_epoch = 0,
                },
            },
        },
    };
    const psk_proposals = [_]Proposal{psk_prop};

    // Alice commits with PSK (no path needed for PSK-only).
    var cr2 = try mls.createCommit(
        Default,
        alloc,
        &cr1.group_context,
        &cr1.tree,
        gs.my_leaf_index,
        &psk_proposals,
        &alice_sign.sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        null,
        resolver,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(alloc);

    try testing.expectEqual(@as(u64, 2), cr2.new_epoch);

    // Bob processes the PSK commit.
    const fc = FramedContent{
        .group_id = cr1.group_context.group_id,
        .epoch = cr1.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr2.commit_bytes[0..cr2.commit_len],
    };

    var pr = try mls.processCommit(
        Default,
        alloc,
        .{
            .fc = &fc,
            .signature = &cr2.signature,
            .confirmation_tag = &cr2.confirmation_tag,
            .proposals = &psk_proposals,
            .sender_verify_key = &alice_sign.pk,
            .psk_resolver = resolver,
        },
        &cr1.group_context,
        &cr1.tree,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(alloc);

    // Both agree on epoch secrets.
    try testing.expectEqual(cr2.new_epoch, pr.new_epoch);
    try testing.expectEqualSlices(
        u8,
        &cr2.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

// ── Test: Mixed Add+Remove in same commit ───────────────────
//
// Create → add B, C, D → commit Remove(B) + Add(E) → verify.

test "mixed Add+Remove: same commit adds and removes" {
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xA2),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "mixed-add-rm",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // Add Bob, Carol, Dave (4 leaves).
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB1, 0xB4, 0xB2);
    var carol_tkp: TestKP = undefined;
    try carol_tkp.init(0xC1, 0xC4, 0xC2);
    var dave_tkp: TestKP = undefined;
    try dave_tkp.init(0xD1, 0xD4, 0xD2);

    const add_three = [_]Proposal{
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = bob_tkp.kp },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = carol_tkp.kp },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = dave_tkp.kp },
            },
        },
    };

    var cr1 = try mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_three,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(alloc);

    try testing.expectEqual(@as(u32, 4), cr1.tree.leaf_count);

    // Now: commit with Remove(Bob, leaf 1) + Add(Eve).
    var eve_tkp: TestKP = undefined;
    try eve_tkp.init(0xE1, 0xE4, 0xE2);

    const mixed_proposals = [_]Proposal{
        // Remove Bob (leaf 1).
        .{
            .tag = .remove,
            .payload = .{ .remove = .{ .removed = 1 } },
        },
        // Add Eve.
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = eve_tkp.kp },
            },
        },
    };

    // Remove requires a path.
    // 4-leaf tree, Alice at leaf 0:
    //   direct path = [1, 3], copath = [2(bob), 5].
    //   Bob (node 2) removed → resolution({}) = 0 seeds.
    //   Node 5: left=4(carol), right=6(dave) → 2 seeds.
    //   But after remove, Add(eve) fills blank leaf 1.
    //   So at commit time the tree before add has 3 members.
    //   Eph seeds: for the copath after remove. Bob leaf is
    //   removed → blank. Eve is added after. We need seeds
    //   for current resolution of each copath node.
    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const eph_seeds = [_][32]u8{
        [_]u8{0xE0} ** 32,
        [_]u8{0xE1} ** 32,
    };

    const new_alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA3),
    );
    const new_alice = makeTestLeafWithKeys(
        &new_alice_enc.pk,
        &alice_sign.pk,
    );

    const pp: mls.PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_alice,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    var cr2 = try mls.createCommit(
        Default,
        alloc,
        &cr1.group_context,
        &cr1.tree,
        gs.my_leaf_index,
        &mixed_proposals,
        &alice_sign.sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(alloc);

    try testing.expectEqual(@as(u64, 2), cr2.new_epoch);

    // Bob's leaf (1) should now be Eve (Add fills blank).
    const leaf1 = try cr2.tree.getLeaf(LeafIndex.fromU32(1));
    try testing.expect(leaf1 != null);
    // Eve's signature key should be in the leaf.
    try testing.expectEqualSlices(
        u8,
        &eve_tkp.sign_pk,
        leaf1.?.signature_key,
    );

    // Carol (leaf 2) and Dave (leaf 3) still present.
    try testing.expect(
        (try cr2.tree.getLeaf(LeafIndex.fromU32(2))) != null,
    );
    try testing.expect(
        (try cr2.tree.getLeaf(LeafIndex.fromU32(3))) != null,
    );

    // Carol processes the commit with path decryption.
    const commit_data = cr2.commit_bytes[0..cr2.commit_len];
    var dec = try mls.Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    const fc = FramedContent{
        .group_id = cr1.group_context.group_id,
        .epoch = cr1.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    const rp: mls.ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(2),
        .receiver_sk = &carol_tkp.enc_sk,
        .receiver_pk = &carol_tkp.enc_pk,
    };

    var pr = try mls.processCommit(
        Default,
        alloc,
        .{
            .fc = &fc,
            .signature = &cr2.signature,
            .confirmation_tag = &cr2.confirmation_tag,
            .proposals = &mixed_proposals,
            .update_path = if (dec.value.path) |*p| p else null,
            .sender_verify_key = &alice_sign.pk,
            .receiver_params = rp,
        },
        &cr1.group_context,
        &cr1.tree,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(alloc);

    // Carol agrees on epoch secrets.
    try testing.expectEqual(cr2.new_epoch, pr.new_epoch);
    try testing.expectEqualSlices(
        u8,
        &cr2.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

// ── Test: Concurrent commits (WrongEpoch) ───────────────────
//
// Create → add B, C → both B and C commit at same epoch →
// second commit rejected with WrongEpoch.

test "concurrent commits: second commit rejected" {
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x11),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0x12),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "concurrent-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // Add Bob and Carol to get a 3-member group.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0x21, 0x24, 0x22);
    var carol_tkp: TestKP = undefined;
    try carol_tkp.init(0x31, 0x34, 0x32);

    const add_two = [_]Proposal{
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = bob_tkp.kp },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = carol_tkp.kp },
            },
        },
    };

    var cr1 = try mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_two,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(alloc);

    try testing.expectEqual(@as(u32, 3), cr1.tree.leaf_count);

    // Both Alice and Bob create commits at epoch 1.
    // Alice's commit: add Dave.
    var dave_tkp: TestKP = undefined;
    try dave_tkp.init(0x41, 0x44, 0x42);

    const add_dave = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = dave_tkp.kp },
        },
    }};

    var cr_alice = try mls.createCommit(
        Default,
        alloc,
        &cr1.group_context,
        &cr1.tree,
        gs.my_leaf_index,
        &add_dave,
        &alice_sign.sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr_alice.tree.deinit();
    defer cr_alice.deinit(alloc);

    // Bob's commit: empty commit with path at same epoch.
    const bob_leaf_secret = [_]u8{0xF1} ** Default.nh;
    // 3-leaf tree, Bob at leaf 1:
    //   Copath = [node 0 (alice), node 4 (carol)].
    //   resolution(alice)={alice}, resolution(carol)={carol}
    //   → 2 eph seeds.
    const bob_eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
        [_]u8{0xE2} ** 32,
    };
    const new_bob_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x25),
    );
    const new_bob_leaf = makeTestLeafWithKeys(
        &new_bob_enc.pk,
        &bob_tkp.sign_pk,
    );
    const bob_pp: mls.PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_bob_leaf,
        .leaf_secret = &bob_leaf_secret,
        .eph_seeds = &bob_eph_seeds,
    };

    const empty = [_]Proposal{};
    var cr_bob = try mls.createCommit(
        Default,
        alloc,
        &cr1.group_context,
        &cr1.tree,
        LeafIndex.fromU32(1),
        &empty,
        &bob_tkp.sign_sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        bob_pp,
        null,
        .mls_public_message,
    );
    defer cr_bob.tree.deinit();
    defer cr_bob.deinit(alloc);

    // Carol processes Alice's commit first (succeeds).
    const fc_alice = FramedContent{
        .group_id = cr1.group_context.group_id,
        .epoch = cr1.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr_alice.commit_bytes[0..cr_alice.commit_len],
    };

    var pr_alice = try mls.processCommit(
        Default,
        alloc,
        .{
            .fc = &fc_alice,
            .signature = &cr_alice.signature,
            .confirmation_tag = &cr_alice.confirmation_tag,
            .proposals = &add_dave,
            .sender_verify_key = &alice_sign.pk,
        },
        &cr1.group_context,
        &cr1.tree,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
    );
    defer pr_alice.tree.deinit();
    defer pr_alice.deinit(alloc);

    try testing.expectEqual(@as(u64, 2), pr_alice.new_epoch);

    // Carol tries to process Bob's commit (same epoch 1).
    // Should fail with WrongEpoch since Carol is now at epoch 2.
    const fc_bob = FramedContent{
        .group_id = cr1.group_context.group_id,
        .epoch = cr1.group_context.epoch,
        .sender = Sender.member(LeafIndex.fromU32(1)),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr_bob.commit_bytes[0..cr_bob.commit_len],
    };

    const bob_commit_data =
        cr_bob.commit_bytes[0..cr_bob.commit_len];
    var dec_bob = try mls.Commit.decode(
        alloc,
        bob_commit_data,
        0,
    );
    defer dec_bob.value.deinit(alloc);

    try testing.expectError(
        error.WrongEpoch,
        mls.processCommit(
            Default,
            alloc,
            .{
                .fc = &fc_bob,
                .signature = &cr_bob.signature,
                .confirmation_tag = &cr_bob.confirmation_tag,
                .proposals = &empty,
                .update_path = if (dec_bob.value.path) |*p|
                    p
                else
                    null,
                .sender_verify_key = &bob_tkp.sign_pk,
            },
            &pr_alice.group_context,
            &pr_alice.tree,
            &pr_alice.interim_transcript_hash,
            &pr_alice.epoch_secrets.init_secret,
        ),
    );
}

// ── Test: GCE proposal end-to-end ───────────────────────────
//
// Create → add B → GCE commit with path → verify extensions
// updated.

test "GCE proposal: extensions updated through commit" {
    const alloc = testing.allocator;

    // Both members must support the extension type we're going
    // to set via GCE. Use a non-default extension type (>5)
    // since default types (1-5) must NOT appear in capabilities.
    const custom_ext_type: mls.ExtensionType = @enumFromInt(
        0xFF01,
    );
    const ext_types = [_]mls.ExtensionType{custom_ext_type};

    // Helper to build leaf with extension support.
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const prop_types = comptime [_]mls.types.ProposalType{};
    const cred_types = comptime [_]mls.types.CredentialType{
        .basic,
    };

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xA2),
    );

    const alice_leaf = LeafNode{
        .encryption_key = &alice_enc.pk,
        .signature_key = &alice_sign.pk,
        .credential = Credential.initBasic(&alice_sign.pk),
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

    var gs = try mls.createGroup(
        Default,
        alloc,
        "gce-test",
        alice_leaf,
        suite,
        &.{},
    );
    defer gs.deinit();

    // Add Bob with extension support.
    const bob_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xB1),
    );
    const bob_init = try Default.dhKeypairFromSeed(
        &testSeed(0xB3),
    );
    const bob_sign = try Default.signKeypairFromSeed(
        &testSeed(0xB2),
    );

    var bob_leaf_sig: [Default.sig_len]u8 = undefined;
    var bob_kp_sig: [Default.sig_len]u8 = undefined;

    var bob_leaf_node = LeafNode{
        .encryption_key = &bob_enc.pk,
        .signature_key = &bob_sign.pk,
        .credential = Credential.initBasic(&bob_sign.pk),
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
        .signature = &bob_leaf_sig,
    };

    try bob_leaf_node.signLeafNode(
        Default,
        &bob_sign.sk,
        &bob_leaf_sig,
        null,
        null,
    );

    var bob_kp = KeyPackage{
        .version = .mls10,
        .cipher_suite = suite,
        .init_key = &bob_init.pk,
        .leaf_node = bob_leaf_node,
        .extensions = &.{},
        .signature = &bob_kp_sig,
    };
    try bob_kp.signKeyPackage(
        Default,
        &bob_sign.sk,
        &bob_kp_sig,
    );

    const add_bob = [_]Proposal{.{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_kp } },
    }};

    var cr1 = try mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_bob,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(alloc);

    // GCE commit: set application_id extension.
    const gce_data = "my-application-id";
    const gce_ext = Extension{
        .extension_type = custom_ext_type,
        .data = gce_data,
    };
    const gce_exts = [_]Extension{gce_ext};
    const gce_prop = Proposal{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{
                .extensions = &gce_exts,
            },
        },
    };
    const gce_proposals = [_]Proposal{gce_prop};

    // GCE requires a path (zmls intentional strictness).
    // 2-leaf tree: copath = [bob's leaf] → 1 eph seed.
    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const eph_seeds = [_][32]u8{[_]u8{0xE0} ** 32};
    const new_alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA3),
    );

    const new_alice_leaf = LeafNode{
        .encryption_key = &new_alice_enc.pk,
        .signature_key = &alice_sign.pk,
        .credential = Credential.initBasic(&alice_sign.pk),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &ext_types,
            .proposals = &prop_types,
            .credentials = &cred_types,
        },
        .source = .commit,
        .lifetime = null,
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };

    const pp: mls.PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_alice_leaf,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    var cr2 = try mls.createCommit(
        Default,
        alloc,
        &cr1.group_context,
        &cr1.tree,
        gs.my_leaf_index,
        &gce_proposals,
        &alice_sign.sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(alloc);

    try testing.expectEqual(@as(u64, 2), cr2.new_epoch);

    // Verify the new group context has the GCE extensions.
    try testing.expectEqual(
        @as(usize, 1),
        cr2.group_context.extensions.len,
    );
    try testing.expectEqual(
        custom_ext_type,
        cr2.group_context.extensions[0].extension_type,
    );
    try testing.expectEqualSlices(
        u8,
        gce_data,
        cr2.group_context.extensions[0].data,
    );

    // Bob processes the GCE commit with path decryption.
    const commit_data = cr2.commit_bytes[0..cr2.commit_len];
    var dec = try mls.Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    const fc = FramedContent{
        .group_id = cr1.group_context.group_id,
        .epoch = cr1.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    const rp: mls.ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(1),
        .receiver_sk = &bob_enc.sk,
        .receiver_pk = &bob_enc.pk,
    };

    var pr = try mls.processCommit(
        Default,
        alloc,
        .{
            .fc = &fc,
            .signature = &cr2.signature,
            .confirmation_tag = &cr2.confirmation_tag,
            .proposals = &gce_proposals,
            .update_path = if (dec.value.path) |*p| p else null,
            .sender_verify_key = &alice_sign.pk,
            .receiver_params = rp,
        },
        &cr1.group_context,
        &cr1.tree,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(alloc);

    // Bob agrees: epoch, secrets, and extensions.
    try testing.expectEqual(cr2.new_epoch, pr.new_epoch);
    try testing.expectEqualSlices(
        u8,
        &cr2.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
    try testing.expectEqual(
        @as(usize, 1),
        pr.group_context.extensions.len,
    );
    try testing.expectEqualSlices(
        u8,
        gce_data,
        pr.group_context.extensions[0].data,
    );
}

test "unified API: commit + applyCommit + joinViaWelcome" {
    const alloc = testing.allocator;

    // 1. Alice creates a group.
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xC1),
    );
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xC2),
    );
    var alice_leaf = makeTestLeafWithKeys(
        &alice_enc.pk,
        &alice_sign.pk,
    );
    alice_leaf.source = .key_package;

    var gs = try mls.createGroup(
        Default,
        alloc,
        "unified-api-group",
        alice_leaf,
        suite,
        &.{},
    );
    defer gs.deinit();

    // 2. Bob key package.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xD1, 0xD3, 0xD2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const proposals = [_]Proposal{add_prop};

    // 3. Unified commit: returns CommitOutput with new state.
    const GS = mls.GroupState(Default);
    var output = try gs.commit(alloc, .{
        .proposals = &proposals,
        .sign_key = &alice_sign.sk,
    });
    defer output.deinit();

    // The new state has epoch 1 and 2 leaves.
    try testing.expectEqual(
        @as(u64, 1),
        output.group_state.epoch(),
    );
    try testing.expectEqual(
        @as(u32, 2),
        output.group_state.leafCount(),
    );

    // 4. Build Welcome from the output.
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = try output.group_state.serializeContext(
        &gc_buf,
    );
    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob_tkp.kp.encode(&kp_buf, 0);
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );
    const eph_seed = [_]u8{0xEE} ** 32;
    const new_members = [_]mls.group_welcome.NewMemberEntry(Default){
        .{
            .kp_ref = &kp_ref,
            .init_pk = &bob_tkp.init_pk,
            .eph_seed = &eph_seed,
            .leaf_index = LeafIndex.fromU32(1),
        },
    };

    var wr = try output.group_state.buildWelcome(alloc, .{
        .gc_bytes = gc_bytes,
        .confirmation_tag = &output.confirmation_tag,
        .welcome_secret = &output.welcome_secret,
        .joiner_secret = &output.joiner_secret,
        .sign_key = &alice_sign.sk,
        .signer = 0,
        .cipher_suite = suite,
        .new_members = &new_members,
        .path_secrets = &output.path_secrets,
        .path_secret_count = output.path_secret_count,
        .fdp_nodes = &output.fdp_nodes,
        .tree_size = output.group_state.tree.leaf_count,
    });
    defer wr.deinit(alloc);

    // 5. Bob joins via Welcome.
    var bob_gs = try GS.joinViaWelcome(alloc, .{
        .welcome = &wr.welcome,
        .kp_ref = &kp_ref,
        .init_sk = &bob_tkp.init_sk,
        .init_pk = &bob_tkp.init_pk,
        .signer_verify_key = &alice_sign.pk,
        .tree_data = .{
            .prebuilt = output.group_state.tree,
        },
        .my_leaf_index = LeafIndex.fromU32(1),
    });
    defer bob_gs.deinit();

    // 6. Verify epoch agreement.
    try testing.expectEqual(@as(u64, 1), bob_gs.epoch());
    try testing.expectEqualSlices(
        u8,
        output.group_state.epochAuthenticator(),
        bob_gs.epochAuthenticator(),
    );
}

// ── Adversarial / negative tests (P6.5) ─────────────────────

test "replay: same commit processed twice rejected" {
    const alloc = testing.allocator;

    // Create 1-member group (Alice).
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xA2),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "replay-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB1, 0xB3, 0xB2);

    var carol_tkp: TestKP = undefined;
    try carol_tkp.init(0xC1, 0xC3, 0xC2);

    // Add Bob (epoch 0 → 1).
    const add_bob = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    }};

    var cr1 = try mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_bob,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(alloc);

    // Add Carol at epoch 1.
    const add_carol = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = carol_tkp.kp },
        },
    }};

    var cr2 = try mls.createCommit(
        Default,
        alloc,
        &cr1.group_context,
        &cr1.tree,
        gs.my_leaf_index,
        &add_carol,
        &alice_sign.sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(alloc);

    const fc2 = FramedContent{
        .group_id = cr1.group_context.group_id,
        .epoch = cr1.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr2.commit_bytes[0..cr2.commit_len],
    };

    // Bob processes Alice's epoch-1 commit (succeeds).
    var pr = try mls.processCommit(
        Default,
        alloc,
        .{
            .fc = &fc2,
            .signature = &cr2.signature,
            .confirmation_tag = &cr2.confirmation_tag,
            .proposals = &add_carol,
            .sender_verify_key = &alice_sign.pk,
        },
        &cr1.group_context,
        &cr1.tree,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(alloc);

    try testing.expectEqual(@as(u64, 2), pr.new_epoch);

    // Replay: Bob tries to process the same commit again.
    // Now Bob is at epoch 2, commit is for epoch 1 → WrongEpoch.
    try testing.expectError(
        error.WrongEpoch,
        mls.processCommit(
            Default,
            alloc,
            .{
                .fc = &fc2,
                .signature = &cr2.signature,
                .confirmation_tag = &cr2.confirmation_tag,
                .proposals = &add_carol,
                .sender_verify_key = &alice_sign.pk,
            },
            &pr.group_context,
            &pr.tree,
            &pr.interim_transcript_hash,
            &pr.epoch_secrets.init_secret,
        ),
    );
}

test "forward secrecy: epoch secrets differ after advance" {
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xF1),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xF2),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "forward-secrecy",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // Capture epoch 0 secrets.
    const epoch0_auth = gs.epoch_secrets.epoch_authenticator;
    const epoch0_init = gs.epoch_secrets.init_secret;

    // Empty commit → epoch 1.
    const empty = [_]Proposal{};
    var cr = try mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &empty,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(alloc);

    // Epoch 1 secrets must differ from epoch 0.
    const epoch1_auth = cr.epoch_secrets.epoch_authenticator;
    const epoch1_init = cr.epoch_secrets.init_secret;

    // Epoch authenticators must differ.
    try testing.expect(!std.mem.eql(
        u8,
        &epoch0_auth,
        &epoch1_auth,
    ));

    // Init secrets must differ.
    try testing.expect(!std.mem.eql(
        u8,
        &epoch0_init,
        &epoch1_init,
    ));

    // Another commit → epoch 2.
    var cr2 = try mls.createCommit(
        Default,
        alloc,
        &cr.group_context,
        &cr.tree,
        gs.my_leaf_index,
        &empty,
        &alice_sign.sk,
        &cr.interim_transcript_hash,
        &cr.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(alloc);

    const epoch2_auth = cr2.epoch_secrets.epoch_authenticator;

    // All three must be mutually distinct.
    try testing.expect(!std.mem.eql(
        u8,
        &epoch1_auth,
        &epoch2_auth,
    ));
    try testing.expect(!std.mem.eql(
        u8,
        &epoch0_auth,
        &epoch2_auth,
    ));
}

test "tampered commit signature rejected" {
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xE1),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xE2),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "tamper-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xE3, 0xE4, 0xE5);

    const add_bob = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    }};

    var cr = try mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_bob,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(alloc);

    // Tamper with the signature: flip one bit.
    var tampered_sig = cr.signature;
    tampered_sig[0] ^= 0x01;

    const fc = FramedContent{
        .group_id = gs.group_context.group_id,
        .epoch = gs.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    // processCommit with tampered signature should fail.
    try testing.expectError(
        error.SignatureVerifyFailed,
        mls.processCommit(
            Default,
            alloc,
            .{
                .fc = &fc,
                .signature = &tampered_sig,
                .confirmation_tag = &cr.confirmation_tag,
                .proposals = &add_bob,
                .sender_verify_key = &alice_sign.pk,
            },
            &gs.group_context,
            &gs.tree,
            &gs.interim_transcript_hash,
            &gs.epoch_secrets.init_secret,
        ),
    );
}

// ── Test: ReInit proposal end-to-end ────────────────────────
//
// Create → add Bob → ReInit-only commit → Bob processes →
// verify has_reinit flag. RFC 9420 S12.2: ReInit must be
// the only proposal in the commit.

test "ReInit proposal: commit with reinit processed by receiver" {
    const alloc = testing.allocator;

    // Alice keys.
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xF3),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xF4),
    );

    // 1. Alice creates the group.
    var gs = try mls.createGroup(
        Default,
        alloc,
        "reinit-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // 2. Add Bob.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xF5, 0xF7, 0xF6);

    const add_bob = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    }};

    var cr1 = try mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_bob,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(alloc);

    try testing.expectEqual(@as(u64, 1), cr1.new_epoch);
    try testing.expectEqual(@as(u32, 2), cr1.tree.leaf_count);

    // 3. Alice creates a ReInit-only commit at epoch 1.
    // ReInit does NOT require a path (isPathRequired returns
    // false for reinit-only commits).
    const reinit_prop = Proposal{
        .tag = .reinit,
        .payload = .{
            .reinit = .{
                .group_id = "new-group-id",
                .version = .mls10,
                .cipher_suite = suite,
                .extensions = &.{},
            },
        },
    };
    const reinit_proposals = [_]Proposal{reinit_prop};

    var cr2 = try mls.createCommit(
        Default,
        alloc,
        &cr1.group_context,
        &cr1.tree,
        gs.my_leaf_index,
        &reinit_proposals,
        &alice_sign.sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(alloc);

    try testing.expectEqual(@as(u64, 2), cr2.new_epoch);

    // Verify Alice's commit result has has_reinit = true.
    try testing.expect(cr2.apply_result.has_reinit);

    // 4. Bob processes the ReInit commit.
    const fc = FramedContent{
        .group_id = cr1.group_context.group_id,
        .epoch = cr1.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr2.commit_bytes[0..cr2.commit_len],
    };

    var pr = try mls.processCommit(
        Default,
        alloc,
        .{
            .fc = &fc,
            .signature = &cr2.signature,
            .confirmation_tag = &cr2.confirmation_tag,
            .proposals = &reinit_proposals,
            .sender_verify_key = &alice_sign.pk,
        },
        &cr1.group_context,
        &cr1.tree,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
    );
    defer pr.tree.deinit();
    defer pr.deinit(alloc);

    // 5. Verify Bob's result has has_reinit = true.
    try testing.expect(pr.apply_result.has_reinit);
    try testing.expectEqual(cr2.new_epoch, pr.new_epoch);

    // Epoch secrets agree.
    try testing.expectEqualSlices(
        u8,
        &cr2.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

// ── Test: Out-of-order stale-epoch commit rejected ──────────
//
// Create 3-member group → Bob creates commit C1 at epoch 0
// (saved) → Alice creates commit C2 at epoch 0 (processed
// first by Carol) → Carol advances to epoch 1 → Carol tries
// Bob's stale commit → WrongEpoch.

test "out-of-order: stale-epoch commit rejected after advancement" {
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA5),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xA6),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "out-of-order-test",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    defer gs.deinit();

    // Add Bob and Carol to get a 3-member group at epoch 1.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xA7, 0xAA, 0xA8);
    var carol_tkp: TestKP = undefined;
    try carol_tkp.init(0xA9, 0xAB, 0xAC);

    const add_two = [_]Proposal{
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = bob_tkp.kp },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = carol_tkp.kp },
            },
        },
    };

    var cr0 = try mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_two,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr0.tree.deinit();
    defer cr0.deinit(alloc);

    try testing.expectEqual(@as(u64, 1), cr0.new_epoch);
    try testing.expectEqual(@as(u32, 3), cr0.tree.leaf_count);

    // Now at epoch 1 with 3 members: Alice(0), Bob(1), Carol(2).

    // Bob creates an empty commit with path at epoch 1.
    // 3-leaf tree, Bob at leaf 1:
    //   Copath = [node 0 (alice), node 4 (carol)].
    //   resolution(alice)={alice}, resolution(carol)={carol}
    //   → 2 eph seeds.
    const bob_leaf_secret = [_]u8{0xF5} ** Default.nh;
    const bob_eph_seeds = [_][32]u8{
        [_]u8{0xE5} ** 32,
        [_]u8{0xE6} ** 32,
    };
    const new_bob_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xAD),
    );
    const new_bob_leaf = makeTestLeafWithKeys(
        &new_bob_enc.pk,
        &bob_tkp.sign_pk,
    );
    const bob_pp: mls.PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_bob_leaf,
        .leaf_secret = &bob_leaf_secret,
        .eph_seeds = &bob_eph_seeds,
    };

    const empty = [_]Proposal{};
    var cr_bob = try mls.createCommit(
        Default,
        alloc,
        &cr0.group_context,
        &cr0.tree,
        LeafIndex.fromU32(1),
        &empty,
        &bob_tkp.sign_sk,
        &cr0.interim_transcript_hash,
        &cr0.epoch_secrets.init_secret,
        bob_pp,
        null,
        .mls_public_message,
    );
    defer cr_bob.tree.deinit();
    defer cr_bob.deinit(alloc);

    // Alice creates a different empty commit with path at the
    // same epoch 1.
    // 3-leaf tree, Alice at leaf 0:
    //   Copath = [node 2 (bob), node 4 (carol)].
    //   resolution(bob)={bob}, resolution(carol)={carol}
    //   → 2 eph seeds.
    const alice_leaf_secret = [_]u8{0xF6} ** Default.nh;
    const alice_eph_seeds = [_][32]u8{
        [_]u8{0xE7} ** 32,
        [_]u8{0xE8} ** 32,
    };
    const new_alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xAE),
    );
    const new_alice_leaf = makeTestLeafWithKeys(
        &new_alice_enc.pk,
        &alice_sign.pk,
    );
    const alice_pp: mls.PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_alice_leaf,
        .leaf_secret = &alice_leaf_secret,
        .eph_seeds = &alice_eph_seeds,
    };

    var cr_alice = try mls.createCommit(
        Default,
        alloc,
        &cr0.group_context,
        &cr0.tree,
        gs.my_leaf_index,
        &empty,
        &alice_sign.sk,
        &cr0.interim_transcript_hash,
        &cr0.epoch_secrets.init_secret,
        alice_pp,
        null,
        .mls_public_message,
    );
    defer cr_alice.tree.deinit();
    defer cr_alice.deinit(alloc);

    // Carol processes Alice's commit first → advances to epoch 2.
    const fc_alice = FramedContent{
        .group_id = cr0.group_context.group_id,
        .epoch = cr0.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr_alice.commit_bytes[0..cr_alice.commit_len],
    };

    const alice_commit_data =
        cr_alice.commit_bytes[0..cr_alice.commit_len];
    var dec_alice = try mls.Commit.decode(
        alloc,
        alice_commit_data,
        0,
    );
    defer dec_alice.value.deinit(alloc);

    const carol_rp: mls.ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(2),
        .receiver_sk = &carol_tkp.enc_sk,
        .receiver_pk = &carol_tkp.enc_pk,
    };

    var pr_alice = try mls.processCommit(
        Default,
        alloc,
        .{
            .fc = &fc_alice,
            .signature = &cr_alice.signature,
            .confirmation_tag = &cr_alice.confirmation_tag,
            .proposals = &empty,
            .update_path = if (dec_alice.value.path) |*p|
                p
            else
                null,
            .sender_verify_key = &alice_sign.pk,
            .receiver_params = carol_rp,
        },
        &cr0.group_context,
        &cr0.tree,
        &cr0.interim_transcript_hash,
        &cr0.epoch_secrets.init_secret,
    );
    defer pr_alice.tree.deinit();
    defer pr_alice.deinit(alloc);

    try testing.expectEqual(@as(u64, 2), pr_alice.new_epoch);

    // Carol tries to process Bob's stale commit (epoch 1, but
    // Carol is now at epoch 2) → should fail with WrongEpoch.
    const fc_bob = FramedContent{
        .group_id = cr0.group_context.group_id,
        .epoch = cr0.group_context.epoch,
        .sender = Sender.member(LeafIndex.fromU32(1)),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr_bob.commit_bytes[0..cr_bob.commit_len],
    };

    const bob_commit_data =
        cr_bob.commit_bytes[0..cr_bob.commit_len];
    var dec_bob = try mls.Commit.decode(
        alloc,
        bob_commit_data,
        0,
    );
    defer dec_bob.value.deinit(alloc);

    try testing.expectError(
        error.WrongEpoch,
        mls.processCommit(
            Default,
            alloc,
            .{
                .fc = &fc_bob,
                .signature = &cr_bob.signature,
                .confirmation_tag = &cr_bob.confirmation_tag,
                .proposals = &empty,
                .update_path = if (dec_bob.value.path) |*p|
                    p
                else
                    null,
                .sender_verify_key = &bob_tkp.sign_pk,
            },
            &pr_alice.group_context,
            &pr_alice.tree,
            &pr_alice.interim_transcript_hash,
            &pr_alice.epoch_secrets.init_secret,
        ),
    );
}

// ── Test: Group with >256 members ───────────────────────────
//
// Create → add 256 members (one per commit, add-only) →
// verify tree handles >256 leaves. Uses a deterministic
// seed helper that avoids u8-wrapping collisions.

/// Generate a unique 32-byte seed from a 16-bit member index
/// and an 8-bit role tag (1=enc, 2=init, 3=sign). This avoids
/// the u8-wrapping collision that testSeed() would hit for
/// member indices ≥ 86 (since 3 tags per member = 258+ values).
fn memberSeed(idx: u16, role: u8) [Default.seed_len]u8 {
    // Use HMAC-SHA256 to derive unique seeds from (idx, role).
    // This guarantees collision-free seeds for up to 65536 members.
    const hi: u8 = @truncate(idx >> 8);
    const lo: u8 = @truncate(idx);
    const key = [_]u8{ hi, lo, role };
    const data = "zmls-test-member-seed";
    var out: [Default.seed_len]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(
        &out,
        data,
        &key,
    );
    return out;
}

test "group with 257 members" {
    const alloc = testing.allocator;

    // Alice (member 0).
    const alice_enc = try Default.dhKeypairFromSeed(
        &memberSeed(0, 1),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &memberSeed(0, 3),
    );

    var gs = try mls.createGroup(
        Default,
        alloc,
        "big-group",
        makeTestLeafWithKeys(&alice_enc.pk, &alice_sign.pk),
        suite,
        &.{},
    );
    // gs is updated in-place across loop iterations; final
    // state is freed by this defer.
    defer gs.deinit();

    try testing.expectEqual(@as(u32, 1), gs.tree.leaf_count);

    // Add 256 more members, one per add-only commit (no path
    // required for add-only commits).
    var i: u16 = 1;
    while (i <= 256) : (i += 1) {
        const enc_kp = try Default.dhKeypairFromSeed(
            &memberSeed(i, 1),
        );
        const init_kp = try Default.dhKeypairFromSeed(
            &memberSeed(i, 2),
        );
        const sign_kp = try Default.signKeypairFromSeed(
            &memberSeed(i, 3),
        );

        // Build a properly signed KeyPackage for member i.
        var leaf_sig_buf: [Default.sig_len]u8 = undefined;
        var kp_sig_buf: [Default.sig_len]u8 = undefined;

        var leaf_node = makeTestLeafWithKeys(
            &enc_kp.pk,
            &sign_kp.pk,
        );
        leaf_node.credential = Credential.initBasic(&sign_kp.pk);
        leaf_node.signature = &leaf_sig_buf;

        try leaf_node.signLeafNode(
            Default,
            &sign_kp.sk,
            &leaf_sig_buf,
            null,
            null,
        );

        var kp = KeyPackage{
            .version = .mls10,
            .cipher_suite = suite,
            .init_key = &init_kp.pk,
            .leaf_node = leaf_node,
            .extensions = &.{},
            .signature = &kp_sig_buf,
        };
        try kp.signKeyPackage(
            Default,
            &sign_kp.sk,
            &kp_sig_buf,
        );

        const add_prop = Proposal{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = kp },
            },
        };
        const proposals = [_]Proposal{add_prop};

        // Create add-only commit (no path needed).
        const cr = try mls.createCommit(
            Default,
            alloc,
            &gs.group_context,
            &gs.tree,
            gs.my_leaf_index,
            &proposals,
            &alice_sign.sk,
            &gs.interim_transcript_hash,
            &gs.epoch_secrets.init_secret,
            null,
            null,
            .mls_public_message,
        );

        // Move new state into gs, freeing old state first.
        // The old tree and group_context are heap-allocated
        // and must be freed before overwriting.
        gs.tree.deinit();
        gs.group_context.deinit(alloc);
        gs.tree = cr.tree;
        gs.group_context = cr.group_context;
        gs.epoch_secrets = cr.epoch_secrets;
        gs.interim_transcript_hash = cr.interim_transcript_hash;
        // Do NOT call cr.deinit() — tree and group_context
        // have been moved into gs.
    }

    try testing.expectEqual(@as(u32, 257), gs.tree.leaf_count);
    try testing.expectEqual(@as(u64, 256), gs.epoch());
}
