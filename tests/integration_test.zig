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
