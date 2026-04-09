const std = @import("std");
const testing = std.testing;

const types = @import("../common/types.zig");
const node_mod = @import("../tree/node.zig");
const hpke_mod = @import("../crypto/hpke.zig");
const proposal_mod = @import("../messages/proposal.zig");
const commit_msg = @import("../messages/commit.zig");
const framing = @import("../framing/content_type.zig");
const framed_content_mod = @import(
    "../framing/framed_content.zig",
);
const state_mod = @import("state.zig");
const external = @import("external.zig");

const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import(
    "../credential/credential.zig",
).Credential;

const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const ExtensionType = types.ExtensionType;
const Extension = node_mod.Extension;
const LeafNode = node_mod.LeafNode;
const Proposal = proposal_mod.Proposal;
const Commit = commit_msg.Commit;
const FramedContent = framed_content_mod.FramedContent;
const Sender = framing.Sender;
const createGroup = state_mod.createGroup;

const deriveExternalKeyPair = external.deriveExternalKeyPair;
const makeExternalPubExtension = external.makeExternalPubExtension;
const extractExternalPub = external.extractExternalPub;
const createExternalInit = external.createExternalInit;
const processExternalInit = external.processExternalInit;
const createExternalCommit = external.createExternalCommit;
const processExternalCommit = external.processExternalCommit;
const resolveExternalInlineProposals = external.resolveExternalInlineProposals;

test "deriveExternalKeyPair is deterministic" {
    const secret = [_]u8{0x42} ** Default.nh;
    const kp1 = try deriveExternalKeyPair(Default, &secret);
    const kp2 = try deriveExternalKeyPair(Default, &secret);

    try testing.expectEqualSlices(u8, &kp1.pk, &kp2.pk);
    try testing.expectEqualSlices(u8, &kp1.sk, &kp2.sk);
}

test "deriveExternalKeyPair produces non-zero output" {
    const secret = [_]u8{0x01} ** Default.nh;
    const kp = try deriveExternalKeyPair(Default, &secret);

    const zero_pk = [_]u8{0} ** Default.npk;
    const zero_sk = [_]u8{0} ** Default.nsk;
    try testing.expect(
        !std.mem.eql(u8, &zero_pk, &kp.pk),
    );
    try testing.expect(
        !std.mem.eql(u8, &zero_sk, &kp.sk),
    );
}

test "deriveExternalKeyPair different secrets give different keys" {
    const secret_a = [_]u8{0xAA} ** Default.nh;
    const secret_b = [_]u8{0xBB} ** Default.nh;
    const kp_a = try deriveExternalKeyPair(Default, &secret_a);
    const kp_b = try deriveExternalKeyPair(Default, &secret_b);

    try testing.expect(
        !std.mem.eql(u8, &kp_a.pk, &kp_b.pk),
    );
}

test "makeExternalPubExtension round-trip with extract" {
    const secret = [_]u8{0x55} ** Default.nh;
    var pk_buf: [Default.npk]u8 = undefined;
    const ext = try makeExternalPubExtension(
        Default,
        &secret,
        &pk_buf,
    );

    // The extension should have external_pub type.
    try testing.expectEqual(
        ExtensionType.external_pub,
        ext.extension_type,
    );
    try testing.expectEqual(
        @as(usize, Default.npk),
        ext.data.len,
    );

    // Extract should recover the same public key.
    const exts = [_]Extension{ext};
    const extracted = try extractExternalPub(Default, &exts);
    try testing.expectEqualSlices(u8, &pk_buf, &extracted);
}

test "extractExternalPub returns MissingExtension when absent" {
    const exts = [_]Extension{};
    const result = extractExternalPub(Default, &exts);
    try testing.expectError(error.MissingExtension, result);
}

test "extractExternalPub returns InvalidPublicKey for wrong size" {
    const bad_ext = Extension{
        .extension_type = .external_pub,
        .data = "too-short",
    };
    const exts = [_]Extension{bad_ext};
    const result = extractExternalPub(Default, &exts);
    try testing.expectError(error.InvalidPublicKey, result);
}

test "createExternalInit and processExternalInit round-trip" {
    // Simulate a group that has derived external_secret.
    const external_secret = [_]u8{0x77} ** Default.nh;

    // Derive the external_pub that would be in GroupInfo.
    const kp = try deriveExternalKeyPair(
        Default,
        &external_secret,
    );

    // Joiner performs Encap.
    const eph_seed = [_]u8{0x88} ** 32;
    var kem_output_buf: [Default.npk]u8 = undefined;
    const joiner_result = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_output_buf,
    );

    // Existing member performs Decap.
    const recovered = try processExternalInit(
        Default,
        joiner_result.proposal.payload
            .external_init.kem_output,
        &external_secret,
    );

    // Both sides should agree on the init_secret.
    try testing.expectEqualSlices(
        u8,
        &joiner_result.init_secret,
        &recovered,
    );
}

test "createExternalInit shared secret is non-zero" {
    const external_secret = [_]u8{0x33} ** Default.nh;
    const kp = try deriveExternalKeyPair(
        Default,
        &external_secret,
    );

    const eph_seed = [_]u8{0x44} ** 32;
    var kem_output_buf: [Default.npk]u8 = undefined;
    const result = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_output_buf,
    );

    const zero = [_]u8{0} ** Default.nh;
    try testing.expect(
        !std.mem.eql(u8, &zero, &result.init_secret),
    );
}

test "processExternalInit rejects wrong kem_output length" {
    const external_secret = [_]u8{0x11} ** Default.nh;
    const short = [_]u8{ 0x01, 0x02, 0x03 };
    const result = processExternalInit(
        Default,
        &short,
        &external_secret,
    );
    try testing.expectError(error.InvalidPublicKey, result);
}

test "processExternalInit with wrong secret gives different result" {
    // Create an ExternalInit with one external_secret.
    const real_secret = [_]u8{0xAA} ** Default.nh;
    const kp = try deriveExternalKeyPair(
        Default,
        &real_secret,
    );

    const eph_seed = [_]u8{0xBB} ** 32;
    var kem_output_buf: [Default.npk]u8 = undefined;
    const joiner_result = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_output_buf,
    );

    // Try to process with a different external_secret.
    // X25519 Decap does not fail on wrong keys — it produces
    // a different shared secret. So we verify mismatch.
    const wrong_secret = [_]u8{0xCC} ** Default.nh;
    const recovered = try processExternalInit(
        Default,
        &kem_output_buf,
        &wrong_secret,
    );

    // The recovered init_secret should NOT match the joiner's.
    try testing.expect(
        !std.mem.eql(
            u8,
            &joiner_result.init_secret,
            &recovered,
        ),
    );
}

test "createExternalInit is deterministic" {
    const external_secret = [_]u8{0xDD} ** Default.nh;
    const kp = try deriveExternalKeyPair(
        Default,
        &external_secret,
    );

    const eph_seed = [_]u8{0xEE} ** 32;
    var kem_buf_1: [Default.npk]u8 = undefined;
    var kem_buf_2: [Default.npk]u8 = undefined;

    const r1 = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_buf_1,
    );
    const r2 = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_buf_2,
    );

    // Same inputs must produce same outputs.
    try testing.expectEqualSlices(
        u8,
        &r1.init_secret,
        &r2.init_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &kem_buf_1,
        &kem_buf_2,
    );
}

test "external key pair matches HPKE encap/decap directly" {
    // Verify that our derived key pair works with raw HPKE
    // encap/decap, confirming correct key derivation.
    const external_secret = [_]u8{0x99} ** Default.nh;
    const kp = try deriveExternalKeyPair(
        Default,
        &external_secret,
    );

    const H = hpke_mod.Hpke(Default);
    const eph_seed = [_]u8{0xAB} ** 32;

    const encap_result = try H.encapDeterministic(
        &kp.pk,
        &eph_seed,
    );
    const decap_result = try H.decap(
        &encap_result.enc,
        &kp.sk,
        &kp.pk,
    );

    try testing.expectEqualSlices(
        u8,
        &encap_result.shared_secret,
        &decap_result,
    );
}

fn makeTestLeafWithPk(
    id: []const u8,
    enc_pk: []const u8,
    sig_pk: []const u8,
) LeafNode {
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

test "createExternalCommit and processExternalCommit round-trip" {
    const alloc = testing.allocator;

    // -- 1. Generate real crypto keys for Alice (existing
    //       member) and Bob (joiner).

    const alice_enc_seed = [_]u8{0xA1} ** 32;
    const alice_enc_kp = try Default.dhKeypairFromSeed(
        &alice_enc_seed,
    );
    const alice_sign_seed = [_]u8{0xA2} ** 32;
    const alice_kp = try Default.signKeypairFromSeed(
        &alice_sign_seed,
    );

    const bob_enc_seed = [_]u8{0xB1} ** 32;
    const bob_enc_kp = try Default.dhKeypairFromSeed(
        &bob_enc_seed,
    );
    const bob_sign_seed = [_]u8{0xB2} ** 32;
    const bob_kp = try Default.signKeypairFromSeed(
        &bob_sign_seed,
    );

    // -- 2. Create a one-member group with Alice at leaf 0.

    const alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );

    var gs = try createGroup(
        Default,
        alloc,
        "ext-commit-test",
        alice_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // -- 3. Build the external_pub extension from Alice's
    //       epoch secrets.

    var ext_pub_buf: [Default.npk]u8 = undefined;
    const ext_pub_ext = try makeExternalPubExtension(
        Default,
        &gs.epoch_secrets.external_secret,
        &ext_pub_buf,
    );
    const gi_extensions = [_]Extension{ext_pub_ext};

    // -- 4. Bob creates an external commit to join the group.
    //
    // Tree before: [Alice] (1 leaf).
    // Bob will be added as leaf 1 → 2-leaf tree.
    // Bob's direct path = [root].
    // Bob's copath = [leaf 0 = Alice].
    // resolution(Alice) = {Alice} → 1 eph seed.

    const bob_leaf = makeTestLeafWithPk(
        "bob",
        &bob_enc_kp.pk,
        &bob_kp.pk,
    );

    const leaf_secret = [_]u8{0xF1} ** Default.nh;
    const ext_init_seed = [_]u8{0xF2} ** 32;
    const eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
    };

    var ec_result = try createExternalCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        &gi_extensions,
        &gs.interim_transcript_hash,
        .{
            .allocator = alloc,
            .joiner_leaf = bob_leaf,
            .sign_key = &bob_kp.sk,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
            .ext_init_seed = &ext_init_seed,
            .remove_proposals = &.{},
        },
        .mls_public_message,
    );
    defer ec_result.tree.deinit();
    defer ec_result.deinit(testing.allocator);

    // -- 5. Alice decodes the Commit to extract proposals
    //       and UpdatePath.

    const commit_data =
        ec_result.commit_bytes[0..ec_result.commit_len];
    var dec = try Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    try testing.expect(dec.value.path != null);

    // Extract inline proposals from ProposalOrRef list.
    const por_list = dec.value.proposals;
    var prop_buf: [257]Proposal = undefined;
    const proposals = try resolveExternalInlineProposals(
        por_list,
        &prop_buf,
    );

    // -- 6. Alice builds FramedContent and calls
    //       processExternalCommit.

    const fc = FramedContent{
        .group_id = gs.group_context.group_id,
        .epoch = gs.group_context.epoch,
        .sender = Sender.newMemberCommit(),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    var proc_result = try processExternalCommit(
        Default,
        testing.allocator,
        &fc,
        &ec_result.signature,
        &ec_result.confirmation_tag,
        proposals,
        &dec.value.path.?,
        &gs.group_context,
        &gs.tree,
        &bob_kp.pk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.external_secret,
        null,
        gs.my_leaf_index, // Alice = leaf 0
        &alice_enc_kp.sk,
        &alice_enc_kp.pk,
        .mls_public_message,
    );
    defer proc_result.tree.deinit();
    defer proc_result.deinit(testing.allocator);

    // -- 7. Verify both sides agree on the new epoch state.

    // New epoch number.
    try testing.expectEqual(
        ec_result.new_epoch,
        proc_result.new_epoch,
    );
    try testing.expectEqual(@as(u64, 1), ec_result.new_epoch);

    // Epoch secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.epoch_secret,
        &proc_result.epoch_secrets.epoch_secret,
    );

    // Init secret (for next epoch).
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.init_secret,
        &proc_result.epoch_secrets.init_secret,
    );

    // Confirmation key.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.confirmation_key,
        &proc_result.epoch_secrets.confirmation_key,
    );

    // Sender data secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.sender_data_secret,
        &proc_result.epoch_secrets.sender_data_secret,
    );

    // Encryption secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.encryption_secret,
        &proc_result.epoch_secrets.encryption_secret,
    );

    // Exporter secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.exporter_secret,
        &proc_result.epoch_secrets.exporter_secret,
    );

    // External secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.external_secret,
        &proc_result.epoch_secrets.external_secret,
    );

    // Membership key.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.membership_key,
        &proc_result.epoch_secrets.membership_key,
    );

    // Resumption PSK.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.resumption_psk,
        &proc_result.epoch_secrets.resumption_psk,
    );

    // Confirmed transcript hash.
    try testing.expectEqualSlices(
        u8,
        &ec_result.confirmed_transcript_hash,
        &proc_result.confirmed_transcript_hash,
    );

    // Interim transcript hash.
    try testing.expectEqualSlices(
        u8,
        &ec_result.interim_transcript_hash,
        &proc_result.interim_transcript_hash,
    );

    // Tree hash.
    try testing.expectEqualSlices(
        u8,
        &ec_result.group_context.tree_hash,
        &proc_result.group_context.tree_hash,
    );

    // Joiner leaf index — both should agree Bob is at
    // the same leaf.
    try testing.expectEqual(
        ec_result.joiner_leaf_index,
        proc_result.joiner_leaf_index,
    );

    // Tree leaf count — should be 2 (Alice + Bob).
    try testing.expectEqual(
        @as(u32, 2),
        ec_result.tree.leaf_count,
    );
    try testing.expectEqual(
        @as(u32, 2),
        proc_result.tree.leaf_count,
    );
}
