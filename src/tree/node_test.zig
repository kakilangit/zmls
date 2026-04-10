const std = @import("std");
const testing = std.testing;

const node_mod = @import("node.zig");
const LeafNode = node_mod.LeafNode;
const ParentNode = node_mod.ParentNode;
const Node = node_mod.Node;
const NodeType = node_mod.NodeType;
const Extension = node_mod.Extension;
const Lifetime = node_mod.Lifetime;
const Capabilities = node_mod.Capabilities;
const encodeExtensionList = node_mod.encodeExtensionList;
const decodeExtensionList = node_mod.decodeExtensionList;
const injectGrease = node_mod.injectGrease;
const deinitGreased = node_mod.deinitGreased;
const max_leaf_encode = node_mod.max_leaf_encode;

const types = @import("../common/types.zig");
const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const ExtensionType = types.ExtensionType;
const ProposalType = types.ProposalType;
const CredentialType = types.CredentialType;
const LeafNodeSource = types.LeafNodeSource;
const LeafIndex = types.LeafIndex;

const cred_mod = @import("../credential/credential.zig");
const Credential = cred_mod.Credential;

const grease_mod = @import("../common/grease.zig");

const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

fn testLeaf(
    source: LeafNodeSource,
    enc_pk: []const u8,
    sig_pk: []const u8,
) LeafNode {
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]ExtensionType{};
    const prop_types = comptime [_]ProposalType{};
    const cred_types = comptime [_]CredentialType{.basic};

    return .{
        .encryption_key = enc_pk,
        .signature_key = sig_pk,
        .credential = Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &ext_types,
            .proposals = &prop_types,
            .credentials = &cred_types,
        },
        .source = source,
        .lifetime = if (source == .key_package) .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        } else null,
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0} ** 64,
    };
}

test "LeafNode round-trip (key_package source)" {
    const alloc = testing.allocator;

    const versions = [_]ProtocolVersion{.mls10};
    const suites = [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = [_]ExtensionType{};
    const prop_types = [_]ProposalType{};
    const cred_types = [_]CredentialType{.basic};

    const leaf = LeafNode{
        .encryption_key = &[_]u8{ 1, 2, 3, 4 },
        .signature_key = &[_]u8{ 5, 6, 7, 8 },
        .credential = Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &ext_types,
            .proposals = &prop_types,
            .credentials = &cred_types,
        },
        .source = .key_package,
        .lifetime = .{ .not_before = 1000, .not_after = 2000 },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{ 0xAA, 0xBB },
    };

    // Encode.
    var buf: [1024]u8 = undefined;
    const end = try leaf.encode(&buf, 0);

    // Decode.
    var decoded_r = try LeafNode.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);
    const d = &decoded_r.value;

    try testing.expectEqualSlices(
        u8,
        leaf.encryption_key,
        d.encryption_key,
    );
    try testing.expectEqualSlices(
        u8,
        leaf.signature_key,
        d.signature_key,
    );
    try testing.expectEqual(
        CredentialType.basic,
        d.credential.tag,
    );
    try testing.expectEqualSlices(
        u8,
        "alice",
        d.credential.payload.basic,
    );
    try testing.expectEqual(
        LeafNodeSource.key_package,
        d.source,
    );
    try testing.expectEqual(@as(u64, 1000), d.lifetime.?.not_before);
    try testing.expectEqual(@as(u64, 2000), d.lifetime.?.not_after);
    try testing.expectEqualSlices(
        u8,
        leaf.signature,
        d.signature,
    );
    try testing.expectEqual(end, decoded_r.pos);
}

test "LeafNode round-trip (update source, no lifetime)" {
    const alloc = testing.allocator;

    const versions = [_]ProtocolVersion{.mls10};
    const suites = [_]CipherSuite{};
    const ext_types = [_]ExtensionType{};
    const prop_types = [_]ProposalType{};
    const cred_types = [_]CredentialType{.basic};

    const leaf = LeafNode{
        .encryption_key = &[_]u8{0x42},
        .signature_key = &[_]u8{0x43},
        .credential = Credential.initBasic("bob"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &ext_types,
            .proposals = &prop_types,
            .credentials = &cred_types,
        },
        .source = .update,
        .lifetime = null,
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xCC},
    };

    var buf: [1024]u8 = undefined;
    const end = try leaf.encode(&buf, 0);

    var decoded_r = try LeafNode.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqual(
        LeafNodeSource.update,
        decoded_r.value.source,
    );
    try testing.expectEqual(
        @as(?Lifetime, null),
        decoded_r.value.lifetime,
    );
}

test "ParentNode round-trip" {
    const alloc = testing.allocator;

    const unmerged = [_]LeafIndex{
        LeafIndex.fromU32(1),
        LeafIndex.fromU32(3),
    };

    const parent = ParentNode{
        .encryption_key = &[_]u8{ 0x10, 0x20, 0x30 },
        .parent_hash = &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD },
        .unmerged_leaves = &unmerged,
    };

    var buf: [256]u8 = undefined;
    const end = try parent.encode(&buf, 0);

    var decoded_r = try ParentNode.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);
    const d = &decoded_r.value;

    try testing.expectEqualSlices(
        u8,
        parent.encryption_key,
        d.encryption_key,
    );
    try testing.expectEqualSlices(
        u8,
        parent.parent_hash,
        d.parent_hash,
    );
    try testing.expectEqual(
        @as(usize, 2),
        d.unmerged_leaves.len,
    );
    try testing.expectEqual(
        @as(u32, 1),
        d.unmerged_leaves[0].toU32(),
    );
    try testing.expectEqual(
        @as(u32, 3),
        d.unmerged_leaves[1].toU32(),
    );
}

test "Node round-trip (leaf variant)" {
    const alloc = testing.allocator;

    const versions = [_]ProtocolVersion{.mls10};
    const suites = [_]CipherSuite{};
    const ext_types = [_]ExtensionType{};
    const prop_types = [_]ProposalType{};
    const cred_types = [_]CredentialType{.basic};

    const leaf = LeafNode{
        .encryption_key = &[_]u8{0x01},
        .signature_key = &[_]u8{0x02},
        .credential = Credential.initBasic("carol"),
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
        .signature = &[_]u8{0xDD},
    };

    const node = Node.initLeaf(leaf);

    var buf: [1024]u8 = undefined;
    const end = try node.encode(&buf, 0);

    var decoded_r = try Node.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqual(
        NodeType.leaf,
        decoded_r.value.node_type,
    );
    try testing.expectEqualSlices(
        u8,
        "carol",
        decoded_r.value.payload.leaf.credential.payload.basic,
    );
}

test "Node round-trip (parent variant)" {
    const alloc = testing.allocator;

    const parent = ParentNode{
        .encryption_key = &[_]u8{0xAB},
        .parent_hash = &[_]u8{},
        .unmerged_leaves = &.{},
    };

    const node = Node.initParent(parent);

    var buf: [128]u8 = undefined;
    const end = try node.encode(&buf, 0);

    var decoded_r = try Node.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqual(
        NodeType.parent,
        decoded_r.value.node_type,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0xAB},
        decoded_r.value.payload.parent.encryption_key,
    );
}

test "Extension round-trip" {
    const alloc = testing.allocator;

    const ext = Extension{
        .extension_type = .application_id,
        .data = "my-app-id",
    };

    var buf: [64]u8 = undefined;
    const end = try ext.encode(&buf, 0);

    var decoded_r = try Extension.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqual(
        ExtensionType.application_id,
        decoded_r.value.extension_type,
    );
    try testing.expectEqualSlices(
        u8,
        "my-app-id",
        decoded_r.value.data,
    );
}

test "Lifetime round-trip" {
    const lt = Lifetime{ .not_before = 100, .not_after = 200 };
    var buf: [16]u8 = undefined;
    const end = try lt.encode(&buf, 0);
    const r = try Lifetime.decode(&buf, 0);
    try testing.expectEqual(@as(u64, 100), r.value.not_before);
    try testing.expectEqual(@as(u64, 200), r.value.not_after);
    try testing.expectEqual(end, r.pos);
}

// -- LeafNode signature tests ------------------------------------------------

test "LeafNode sign/verify with update source" {
    const enc_kp = try Default.dhKeypairFromSeed(
        &([_]u8{0xA1} ** 32),
    );
    const sign_kp = try Default.signKeypairFromSeed(
        &([_]u8{0xA2} ** 32),
    );

    var sig_buf: [Default.sig_len]u8 = undefined;
    const group_id = "test-group-id";
    const li = LeafIndex.fromU32(2);

    var leaf = testLeaf(.update, &enc_kp.pk, &sign_kp.pk);
    try leaf.signLeafNode(
        Default,
        &sign_kp.sk,
        &sig_buf,
        group_id,
        li,
    );

    // Verify succeeds with correct context.
    try leaf.verifyLeafNodeSignature(Default, group_id, li);
}

test "LeafNode verify rejects wrong group_id" {
    const enc_kp = try Default.dhKeypairFromSeed(
        &([_]u8{0xB1} ** 32),
    );
    const sign_kp = try Default.signKeypairFromSeed(
        &([_]u8{0xB2} ** 32),
    );

    var sig_buf: [Default.sig_len]u8 = undefined;
    const li = LeafIndex.fromU32(0);

    var leaf = testLeaf(.commit, &enc_kp.pk, &sign_kp.pk);
    try leaf.signLeafNode(
        Default,
        &sign_kp.sk,
        &sig_buf,
        "correct-group",
        li,
    );

    // Wrong group_id should fail.
    const result = leaf.verifyLeafNodeSignature(
        Default,
        "wrong-group",
        li,
    );
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
}

test "LeafNode verify rejects wrong leaf_index" {
    const enc_kp = try Default.dhKeypairFromSeed(
        &([_]u8{0xC1} ** 32),
    );
    const sign_kp = try Default.signKeypairFromSeed(
        &([_]u8{0xC2} ** 32),
    );

    var sig_buf: [Default.sig_len]u8 = undefined;
    const group_id = "my-group";

    var leaf = testLeaf(.update, &enc_kp.pk, &sign_kp.pk);
    try leaf.signLeafNode(
        Default,
        &sign_kp.sk,
        &sig_buf,
        group_id,
        LeafIndex.fromU32(5),
    );

    // Wrong leaf_index should fail.
    const result = leaf.verifyLeafNodeSignature(
        Default,
        group_id,
        LeafIndex.fromU32(6),
    );
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
}

test "LeafNode sign/verify key_package source (no context)" {
    const enc_kp = try Default.dhKeypairFromSeed(
        &([_]u8{0xD1} ** 32),
    );
    const sign_kp = try Default.signKeypairFromSeed(
        &([_]u8{0xD2} ** 32),
    );

    var sig_buf: [Default.sig_len]u8 = undefined;

    var leaf = testLeaf(.key_package, &enc_kp.pk, &sign_kp.pk);
    try leaf.signLeafNode(
        Default,
        &sign_kp.sk,
        &sig_buf,
        null,
        null,
    );

    // Verify succeeds with null context.
    try leaf.verifyLeafNodeSignature(Default, null, null);
}

test "encodeSignContent adds context for update source" {
    const enc_kp = try Default.dhKeypairFromSeed(
        &([_]u8{0xE1} ** 32),
    );
    const sign_kp = try Default.signKeypairFromSeed(
        &([_]u8{0xE2} ** 32),
    );

    const leaf = testLeaf(.update, &enc_kp.pk, &sign_kp.pk);

    // Base TBS (no context).
    var buf1: [max_leaf_encode]u8 = undefined;
    const end1 = try leaf.encodeTbs(&buf1, 0);

    // Full sign content (with context).
    var buf2: [max_leaf_encode]u8 = undefined;
    const end2 = try leaf.encodeSignContent(
        &buf2,
        0,
        "gid",
        LeafIndex.fromU32(1),
    );

    // Sign content must be longer (group_id + leaf_index).
    try testing.expect(end2 > end1);

    // Base portion must match.
    try testing.expectEqualSlices(
        u8,
        buf1[0..end1],
        buf2[0..end1],
    );
}

test "encodeSignContent no context for key_package" {
    const enc_kp = try Default.dhKeypairFromSeed(
        &([_]u8{0xF1} ** 32),
    );
    const sign_kp = try Default.signKeypairFromSeed(
        &([_]u8{0xF2} ** 32),
    );

    const leaf = testLeaf(.key_package, &enc_kp.pk, &sign_kp.pk);

    var buf1: [max_leaf_encode]u8 = undefined;
    const end1 = try leaf.encodeTbs(&buf1, 0);

    var buf2: [max_leaf_encode]u8 = undefined;
    const end2 = try leaf.encodeSignContent(
        &buf2,
        0,
        null,
        null,
    );

    // key_package source: no context appended, same length.
    try testing.expectEqual(end1, end2);
    try testing.expectEqualSlices(
        u8,
        buf1[0..end1],
        buf2[0..end2],
    );
}

test "decodeExtensionList rejects duplicate extension types" {
    const alloc = testing.allocator;

    // Encode two extensions with the same type.
    const ext_a = Extension{
        .extension_type = .application_id,
        .data = "aaa",
    };
    const ext_b = Extension{
        .extension_type = .application_id,
        .data = "bbb",
    };
    const exts = [_]Extension{ ext_a, ext_b };

    var buf: [256]u8 = undefined;
    const end = try encodeExtensionList(&buf, 0, &exts);

    const result = decodeExtensionList(alloc, &buf, 0);
    _ = end;
    try testing.expectError(
        error.DuplicateExtensionType,
        result,
    );
}

test "validate rejects leaf whose caps miss required_capabilities" {
    // Build a required_capabilities extension requiring
    // extension type 0xBEEF, which is NOT in the leaf caps.
    // Format: three var-vectors of u16.
    // ext_types: length=2, value=0xBEEF.
    // prop_types: length=0.
    // cred_types: length=0.
    const reqcap_data = [_]u8{
        0x02, 0xBE, 0xEF, // ext_types: len=2, [0xBEEF]
        0x00, // prop_types: len=0
        0x00, // cred_types: len=0
    };
    const ext = Extension{
        .extension_type = .required_capabilities,
        .data = &reqcap_data,
    };
    const extensions = [_]Extension{ext};

    // Leaf with basic credential, empty capabilities.
    const leaf = LeafNode{
        .encryption_key = &.{},
        .signature_key = &.{},
        .credential = .{
            .tag = .basic,
            .payload = .{ .basic = &.{} },
        },
        .capabilities = .{
            .versions = &.{},
            .cipher_suites = &.{
                .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            },
            .extensions = &.{}, // missing 0xBEEF
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .extensions = &extensions,
        .signature = &.{},
        .lifetime = null,
        .parent_hash = null,
    };

    const result = leaf.validate(
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        null,
    );
    try std.testing.expectError(error.InvalidLeafNode, result);
}

test "validate accepts leaf whose caps satisfy required_capabilities" {
    const reqcap_data = [_]u8{
        0x02, 0xBE, 0xEF, // ext_types: len=2, [0xBEEF]
        0x00, // prop_types: len=0
        0x00, // cred_types: len=0
    };
    const ext = Extension{
        .extension_type = .required_capabilities,
        .data = &reqcap_data,
    };
    const extensions = [_]Extension{ext};

    const beef_ext: ExtensionType = @enumFromInt(0xBEEF);
    const leaf = LeafNode{
        .encryption_key = &.{},
        .signature_key = &.{},
        .credential = .{
            .tag = .basic,
            .payload = .{ .basic = &.{} },
        },
        .capabilities = .{
            .versions = &.{.mls10},
            .cipher_suites = &.{
                .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            },
            .extensions = &.{beef_ext}, // has 0xBEEF
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .extensions = &extensions,
        .signature = &.{},
        .lifetime = null,
        .parent_hash = null,
    };

    // Should succeed.
    try leaf.validate(
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        null,
    );
}

test "injectGrease appends GREASE to empty capabilities" {
    const allocator = testing.allocator;
    const empty_versions = [_]ProtocolVersion{.mls10};
    const empty_suites = [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const caps = Capabilities{
        .versions = &empty_versions,
        .cipher_suites = &empty_suites,
        .extensions = &.{},
        .proposals = &.{},
        .credentials = &.{},
    };
    var greased = try injectGrease(allocator, &caps);
    defer deinitGreased(allocator, &greased);

    try testing.expectEqual(@as(usize, 1), greased.extensions.len);
    try testing.expect(
        grease_mod.isGreaseExtension(greased.extensions[0]),
    );
    try testing.expectEqual(@as(usize, 1), greased.proposals.len);
    try testing.expect(
        grease_mod.isGreaseProposal(greased.proposals[0]),
    );
    try testing.expectEqual(@as(usize, 1), greased.credentials.len);
    try testing.expect(
        grease_mod.isGreaseCredential(greased.credentials[0]),
    );
}

test "injectGrease preserves existing entries" {
    const allocator = testing.allocator;
    const versions = [_]ProtocolVersion{.mls10};
    const suites = [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = [_]ExtensionType{.ratchet_tree};
    const cred_types = [_]CredentialType{.basic};
    const caps = Capabilities{
        .versions = &versions,
        .cipher_suites = &suites,
        .extensions = &ext_types,
        .proposals = &.{},
        .credentials = &cred_types,
    };
    var greased = try injectGrease(allocator, &caps);
    defer deinitGreased(allocator, &greased);

    try testing.expectEqual(@as(usize, 2), greased.extensions.len);
    try testing.expectEqual(
        ExtensionType.ratchet_tree,
        greased.extensions[0],
    );
    try testing.expect(
        grease_mod.isGreaseExtension(greased.extensions[1]),
    );
    try testing.expectEqual(@as(usize, 2), greased.credentials.len);
    try testing.expectEqual(
        CredentialType.basic,
        greased.credentials[0],
    );
    try testing.expect(
        grease_mod.isGreaseCredential(greased.credentials[1]),
    );
}

test "injectGrease skips duplicate GREASE" {
    const allocator = testing.allocator;
    const versions = [_]ProtocolVersion{.mls10};
    const suites = [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = [_]ExtensionType{
        @enumFromInt(0x0A0A),
    };
    const caps = Capabilities{
        .versions = &versions,
        .cipher_suites = &suites,
        .extensions = &ext_types,
        .proposals = &.{},
        .credentials = &.{},
    };
    var greased = try injectGrease(allocator, &caps);
    defer deinitGreased(allocator, &greased);

    try testing.expectEqual(@as(usize, 1), greased.extensions.len);
    try testing.expect(
        grease_mod.isGreaseExtension(greased.extensions[0]),
    );
}

test "GREASE capabilities survive LeafNode encode/decode" {
    const allocator = testing.allocator;

    const versions = [_]ProtocolVersion{.mls10};
    const suites = [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const cred_types = [_]CredentialType{.basic};
    const base_caps = Capabilities{
        .versions = &versions,
        .cipher_suites = &suites,
        .extensions = &.{},
        .proposals = &.{},
        .credentials = &cred_types,
    };
    var greased = try injectGrease(allocator, &base_caps);
    defer deinitGreased(allocator, &greased);

    const dummy_key = [_]u8{0xAA} ** 32;
    const leaf = LeafNode{
        .encryption_key = &dummy_key,
        .signature_key = &dummy_key,
        .credential = Credential.initBasic(&dummy_key),
        .capabilities = greased,
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &([_]u8{0xBB} ** 64),
    };

    var buf: [4096]u8 = undefined;
    const end = try leaf.encode(&buf, 0);

    var dec = try LeafNode.decode(allocator, &buf, 0);
    defer dec.value.deinit(allocator);

    try testing.expectEqual(end, dec.pos);

    var found_ext = false;
    for (dec.value.capabilities.extensions) |e| {
        if (grease_mod.isGreaseExtension(e)) found_ext = true;
    }
    try testing.expect(found_ext);

    var found_prop = false;
    for (dec.value.capabilities.proposals) |p| {
        if (grease_mod.isGreaseProposal(p)) found_prop = true;
    }
    try testing.expect(found_prop);

    var found_cred = false;
    for (dec.value.capabilities.credentials) |c| {
        if (grease_mod.isGreaseCredential(c)) found_cred = true;
    }
    try testing.expect(found_cred);
}
