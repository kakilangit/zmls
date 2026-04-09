const std = @import("std");
const testing = std.testing;

const types = @import("../common/types.zig");
const node_mod = @import("../tree/node.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const tree_hashes = @import("../tree/hashes.zig");
const context_mod = @import("context.zig");
const state_mod = @import("state.zig");
const schedule = @import("../key_schedule/schedule.zig");
const welcome_msg = @import("../messages/welcome.zig");
const group_info_mod = @import("../messages/group_info.zig");
const primitives = @import("../crypto/primitives.zig");
const psk_lookup_mod = @import(
    "../key_schedule/psk_lookup.zig",
);
const psk_mod = @import("../key_schedule/psk.zig");
const commit_mod = @import("commit.zig");
const proposal_mod = @import("../messages/proposal.zig");
const key_package_mod = @import("../messages/key_package.zig");
const codec = @import("../codec/codec.zig");
const path_mod = @import("../tree/path.zig");

const welcome = @import("welcome.zig");

const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import(
    "../credential/credential.zig",
).Credential;

const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const LeafIndex = types.LeafIndex;
const Extension = node_mod.Extension;
const LeafNode = node_mod.LeafNode;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const max_gc_encode = context_mod.max_gc_encode;
const GroupSecrets = welcome_msg.GroupSecrets;
const EncryptedGroupSecrets = welcome_msg.EncryptedGroupSecrets;
const Welcome = welcome_msg.Welcome;
const GroupInfo = group_info_mod.GroupInfo;
const Proposal = proposal_mod.Proposal;
const KeyPackage = key_package_mod.KeyPackage;
const HPKECiphertext = path_mod.HPKECiphertext;

const createGroup = state_mod.createGroup;
const createCommit = commit_mod.createCommit;
const processWelcome = welcome.processWelcome;
const buildWelcome = welcome.buildWelcome;
const NewMemberEntry = welcome.NewMemberEntry;
const validateTreeLeaves = welcome.validateTreeLeaves;
const validateKeyUniqueness = welcome.validateKeyUniqueness;
const validateJoinerExtSupport = welcome.validateJoinerExtSupport;

const max_gi_buf: u32 = 65536;

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
