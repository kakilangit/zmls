const std = @import("std");
const testing = std.testing;
const codec = @import("../codec/codec.zig");
const types = @import("../common/types.zig");
const node_mod = @import("../tree/node.zig");
const kp_mod = @import("key_package.zig");
const psk_mod = @import("../key_schedule/psk.zig");
const proposal_mod = @import("proposal.zig");

const ProposalType = types.ProposalType;
const CipherSuite = types.CipherSuite;
const ProtocolVersion = types.ProtocolVersion;
const CredentialType = types.CredentialType;
const ExtensionType = types.ExtensionType;
const KeyPackage = kp_mod.KeyPackage;
const PreSharedKeyId = psk_mod.PreSharedKeyId;
const Credential = @import("../credential/credential.zig")
    .Credential;
const Default = @import("../crypto/default.zig")
    .DhKemX25519Sha256Aes128GcmEd25519;
const Proposal = proposal_mod.Proposal;

test "Proposal Add round-trip" {
    const alloc = testing.allocator;

    // Build a minimal KeyPackage for the Add proposal.
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]ExtensionType{};
    const prop_types = comptime [_]ProposalType{};
    const cred_types = comptime [_]CredentialType{.basic};

    const kp = KeyPackage{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .init_key = &[_]u8{0x01} ** 32,
        .leaf_node = .{
            .encryption_key = &[_]u8{0x02} ** 32,
            .signature_key = &[_]u8{0x03} ** 32,
            .credential = Credential.initBasic("bob"),
            .capabilities = .{
                .versions = &versions,
                .cipher_suites = &suites,
                .extensions = &ext_types,
                .proposals = &prop_types,
                .credentials = &cred_types,
            },
            .source = .key_package,
            .lifetime = .{
                .not_before = 100,
                .not_after = 200,
            },
            .parent_hash = null,
            .extensions = &.{},
            .signature = &[_]u8{0xAA} ** 4,
        },
        .extensions = &.{},
        .signature = &[_]u8{0xBB} ** 4,
    };

    const prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = kp } },
    };

    var buf: [4096]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(ProposalType.add, dec_r.value.tag);
    try testing.expectEqual(
        ProtocolVersion.mls10,
        dec_r.value.payload.add.key_package.version,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "Proposal Remove round-trip" {
    const alloc = testing.allocator;

    const prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 42 } },
    };

    var buf: [64]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProposalType.remove,
        dec_r.value.tag,
    );
    try testing.expectEqual(
        @as(u32, 42),
        dec_r.value.payload.remove.removed,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "Proposal PreSharedKey round-trip" {
    const alloc = testing.allocator;

    const psk_id = PreSharedKeyId{
        .psk_type = .external,
        .external_psk_id = "my-psk",
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = "nonce123",
    };

    const prop = Proposal{
        .tag = .psk,
        .payload = .{ .psk = .{ .psk = psk_id } },
    };

    var buf: [256]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(ProposalType.psk, dec_r.value.tag);
    try testing.expectEqual(
        psk_mod.PskType.external,
        dec_r.value.payload.psk.psk.psk_type,
    );
}

test "Proposal ExternalInit round-trip" {
    const alloc = testing.allocator;

    const prop = Proposal{
        .tag = .external_init,
        .payload = .{
            .external_init = .{
                .kem_output = "kem-out-data",
            },
        },
    };

    var buf: [256]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProposalType.external_init,
        dec_r.value.tag,
    );
    try testing.expectEqualSlices(
        u8,
        "kem-out-data",
        dec_r.value.payload.external_init.kem_output,
    );
}

test "Proposal ReInit round-trip" {
    const alloc = testing.allocator;

    const prop = Proposal{
        .tag = .reinit,
        .payload = .{
            .reinit = .{
                .group_id = "new-group",
                .version = .mls10,
                .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
                .extensions = &.{},
            },
        },
    };

    var buf: [256]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProposalType.reinit,
        dec_r.value.tag,
    );
    try testing.expectEqualSlices(
        u8,
        "new-group",
        dec_r.value.payload.reinit.group_id,
    );
    try testing.expectEqual(
        ProtocolVersion.mls10,
        dec_r.value.payload.reinit.version,
    );
}

test "Proposal GroupContextExtensions round-trip" {
    const alloc = testing.allocator;

    const prop = Proposal{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{
                .extensions = &.{},
            },
        },
    };

    var buf: [64]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProposalType.group_context_extensions,
        dec_r.value.tag,
    );
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.payload
            .group_context_extensions.extensions.len,
    );
}

test "Proposal makeRef is deterministic" {
    const prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 7 } },
    };

    const ref1 = try prop.makeRef(Default);
    const ref2 = try prop.makeRef(Default);
    try testing.expectEqualSlices(u8, &ref1, &ref2);
    try testing.expectEqual(@as(usize, 32), ref1.len);
}

test "Proposal decode accepts unknown/GREASE type" {
    const alloc = testing.allocator;
    var buf: [4]u8 = undefined;
    _ = try codec.encodeUint16(&buf, 0, 0xFFFF);
    var dec_r = try Proposal.decode(alloc, &buf, 0);
    defer dec_r.value.deinit(alloc);

    // Tag preserves the raw value.
    try testing.expectEqual(
        @as(u16, 0xFFFF),
        @intFromEnum(dec_r.value.tag),
    );
    // Payload is the unknown variant with empty body.
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.payload.unknown.len,
    );
    // Position advanced past the 2-byte tag only.
    try testing.expectEqual(@as(u32, 2), dec_r.pos);
}

test "Proposal unknown/GREASE encode round-trip" {
    const alloc = testing.allocator;
    const grease_tag: ProposalType = @enumFromInt(0x0A0A);
    const prop = Proposal{
        .tag = grease_tag,
        .payload = .{ .unknown = &.{} },
    };

    var buf: [4]u8 = undefined;
    const end = try prop.encode(&buf, 0);
    try testing.expectEqual(@as(u32, 2), end);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(grease_tag, dec_r.value.tag);
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.payload.unknown.len,
    );
}

test "Proposal skipDecode handles unknown type" {
    var buf: [4]u8 = undefined;
    _ = try codec.encodeUint16(&buf, 0, 0x0A0A);
    const p = try Proposal.skipDecode(&buf, 0);
    // Advances past 2-byte tag, zero-length body.
    try testing.expectEqual(@as(u32, 2), p);
}
