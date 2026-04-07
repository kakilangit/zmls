//! Binary serializer/deserializer for GroupState. Produces a
//! compact wire format with magic header, epoch secrets, tree
//! nodes, and proposal cache entries.
// GroupState binary serializer/deserializer.
//
// Provides serialize/deserialize for GroupState(P) to a compact
// binary format. Secrets are included — callers MUST secureZero
// the returned buffer after use.
//
// Wire format:
//   magic("ZMLS") version(u8) nh(u8) nk(u8) nn(u8)
//   wire_format_policy(u8) my_leaf_index(u32-be)
//   group_context(varint-len + bytes)
//   epoch_secrets(12 * nh raw bytes)
//   interim_transcript_hash(nh bytes)
//   confirmed_transcript_hash(nh bytes)
//   leaf_count(u32-be)
//   for each node: tag(u8) [varint-len + Node.encode bytes]

const std = @import("std");
const assert = std.debug.assert;
const secureZero = std.crypto.secureZero;
const types = @import("../common/types.zig");
const err = @import("../common/errors.zig");
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const node_mod = @import("../tree/node.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const tree_math = @import("../tree/math.zig");
const context_mod = @import("context.zig");
const schedule = @import("../key_schedule/schedule.zig");
const proposal_cache_mod = @import("proposal_cache.zig");
const epoch_key_ring_mod = @import(
    "../key_schedule/epoch_key_ring.zig",
);
const psk_lookup_mod = @import(
    "../key_schedule/psk_lookup.zig",
);
const state_mod = @import("state.zig");

const LeafIndex = types.LeafIndex;
const NodeIndex = types.NodeIndex;
const Node = node_mod.Node;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const EncodeError = codec.EncodeError;
const DecodeError = err.DecodeError;

const magic: [4]u8 = .{ 'Z', 'M', 'L', 'S' };
const format_version: u8 = 1;

/// Maximum encode buffer for a single node (generous).
const max_node_encode: u32 = 16384;
/// Maximum encode buffer for group context.
const max_gc_encode: u32 = context_mod.max_gc_encode;

/// Number of secret fields in EpochSecrets.
const epoch_secret_count: u32 = 12;

pub fn Serializer(comptime P: type) type {
    return struct {
        const GS = state_mod.GroupState(P);
        const GC = context_mod.GroupContext(P.nh);

        /// Serialize GroupState to a byte buffer.
        /// The caller owns the returned slice.
        /// The caller MUST call secureZero after use.
        pub fn serialize(
            allocator: std.mem.Allocator,
            gs: *const GS,
        ) (EncodeError || error{OutOfMemory})![]u8 {
            const size = try estimateSize(gs);
            const buf = allocator.alloc(
                u8,
                size,
            ) catch return error.OutOfMemory;
            errdefer {
                secureZero(u8, @volatileCast(buf));
                allocator.free(buf);
            }
            var pos: u32 = 0;
            pos = try writeHeader(buf, pos, gs);
            pos = try writeContext(buf, pos, gs);
            pos = try writeSecrets(buf, pos, gs);
            pos = try writeTree(buf, pos, gs);
            // Shrink to exact size so caller can free.
            if (allocator.resize(buf, pos)) {
                return buf[0..pos];
            }
            const exact = allocator.alloc(
                u8,
                pos,
            ) catch return error.OutOfMemory;
            @memcpy(exact, buf[0..pos]);
            secureZero(u8, @volatileCast(buf));
            allocator.free(buf);
            return exact;
        }

        /// Deserialize GroupState from bytes.
        pub fn deserialize(
            allocator: std.mem.Allocator,
            data: []const u8,
        ) (DecodeError || error{OutOfMemory})!GS {
            var pos: u32 = 0;
            pos = try readHeader(data, pos);
            const hdr = try readFieldHeader(data, pos);
            pos = hdr.pos;
            const gc_r = try readGroupContext(
                allocator,
                data,
                pos,
            );
            pos = gc_r.pos;
            var result: GS = undefined;
            result.group_context = gc_r.value;
            errdefer result.group_context.deinit(allocator);
            result.wire_format_policy = hdr.wfp;
            result.my_leaf_index = hdr.leaf_idx;
            pos = try readSecrets(data, pos, &result);
            errdefer result.epoch_secrets.zeroize();
            const tree = try readTree(allocator, data, pos);
            result.tree = tree.value;
            initEmptyRings(&result, allocator);
            return result;
        }

        /// Free a deserialized GroupState. Now that RatchetTree
        /// tracks owns_contents, this is equivalent to gs.deinit().
        /// Kept as a thin wrapper for backward compatibility.
        pub fn deinitDeserialized(gs: *GS) void {
            gs.deinit();
        }

        fn initEmptyRings(
            result: *GS,
            allocator: std.mem.Allocator,
        ) void {
            result.pending_proposals =
                proposal_cache_mod.ProposalCache(P).init();
            result.epoch_key_ring =
                epoch_key_ring_mod.EpochKeyRing(P).init(0);
            result.resumption_psk_ring =
                psk_lookup_mod.ResumptionPskRing(P).init(0);
            result.allocator = allocator;
        }

        // -- Encode helpers (each under 70 lines) ------

        fn writeHeader(
            buf: []u8,
            pos: u32,
            gs: *const GS,
        ) EncodeError!u32 {
            var p = pos;
            if (p + 4 > buf.len) return error.BufferTooSmall;
            @memcpy(buf[p..][0..4], &magic);
            p += 4;
            p = try codec.encodeUint8(buf, p, format_version);
            p = try codec.encodeUint8(buf, p, @intCast(P.nh));
            p = try codec.encodeUint8(buf, p, @intCast(P.nk));
            p = try codec.encodeUint8(buf, p, @intCast(P.nn));
            p = try codec.encodeUint8(
                buf,
                p,
                @intFromEnum(gs.wire_format_policy),
            );
            p = try codec.encodeUint32(
                buf,
                p,
                gs.my_leaf_index.toU32(),
            );
            return p;
        }

        fn writeContext(
            buf: []u8,
            pos: u32,
            gs: *const GS,
        ) EncodeError!u32 {
            var gc_buf: [max_gc_encode]u8 = undefined;
            const gc_end = try gs.group_context.encode(
                &gc_buf,
                0,
            );
            return varintPrefixedCopy(
                buf,
                pos,
                gc_buf[0..gc_end],
            );
        }

        fn writeSecrets(
            buf: []u8,
            pos: u32,
            gs: *const GS,
        ) EncodeError!u32 {
            var p = pos;
            const secrets = &gs.epoch_secrets;
            p = try writeRawFields(buf, p, secrets);
            p = try copyRaw(
                buf,
                p,
                &gs.interim_transcript_hash,
            );
            p = try copyRaw(
                buf,
                p,
                &gs.confirmed_transcript_hash,
            );
            return p;
        }

        fn writeRawFields(
            buf: []u8,
            pos: u32,
            secrets: *const schedule.EpochSecrets(P),
        ) EncodeError!u32 {
            var p = pos;
            inline for (std.meta.fields(
                schedule.EpochSecrets(P),
            )) |field| {
                if (field.type == [P.nh]u8) {
                    p = try copyRaw(
                        buf,
                        p,
                        &@field(secrets, field.name),
                    );
                }
            }
            return p;
        }

        fn writeTree(
            buf: []u8,
            pos: u32,
            gs: *const GS,
        ) EncodeError!u32 {
            var p = try codec.encodeUint32(
                buf,
                pos,
                gs.tree.leaf_count,
            );
            const width = tree_math.nodeWidth(
                gs.tree.leaf_count,
            );
            var i: u32 = 0;
            while (i < width) : (i += 1) {
                p = try writeNode(buf, p, gs.tree.nodes[i]);
            }
            return p;
        }

        fn writeNode(
            buf: []u8,
            pos: u32,
            maybe_node: ?Node,
        ) EncodeError!u32 {
            const node = maybe_node orelse {
                return codec.encodeUint8(buf, pos, 0);
            };
            var p = pos;
            const tag: u8 = switch (node.node_type) {
                .leaf => 1,
                .parent => 2,
            };
            p = try codec.encodeUint8(buf, p, tag);
            var tmp: [max_node_encode]u8 = undefined;
            const n_end = try node.encode(&tmp, 0);
            p = try varintPrefixedCopy(
                buf,
                p,
                tmp[0..n_end],
            );
            return p;
        }

        fn estimateSize(gs: *const GS) EncodeError!u32 {
            var size: u32 = 4 + 1 + 1 + 1 + 1; // magic+ver+nh+nk+nn
            size += 1 + 4; // wire_format_policy + leaf_index
            size += max_gc_encode; // group_context upper bound
            size += epoch_secret_count * P.nh;
            size += P.nh * 2; // transcript hashes
            size += 4; // leaf_count
            const width = tree_math.nodeWidth(
                gs.tree.leaf_count,
            );
            // Per node: 1 tag + 4 varint + max_node_encode.
            size += width * (1 + 4 + max_node_encode);
            return size;
        }

        // -- Decode helpers (each under 70 lines) ------

        fn readHeader(
            data: []const u8,
            pos: u32,
        ) DecodeError!u32 {
            var p = pos;
            if (p + 4 > data.len) return error.Truncated;
            if (!std.mem.eql(u8, data[p..][0..4], &magic)) {
                return error.InvalidEnumValue;
            }
            p += 4;
            const ver = try codec.decodeUint8(data, p);
            if (ver.value != format_version) {
                return error.InvalidEnumValue;
            }
            p = ver.pos;
            const nh_r = try codec.decodeUint8(data, p);
            if (nh_r.value != P.nh) {
                return error.InvalidEnumValue;
            }
            p = nh_r.pos;
            const nk_r = try codec.decodeUint8(data, p);
            if (nk_r.value != P.nk) {
                return error.InvalidEnumValue;
            }
            p = nk_r.pos;
            const nn_r = try codec.decodeUint8(data, p);
            if (nn_r.value != P.nn) {
                return error.InvalidEnumValue;
            }
            return nn_r.pos;
        }

        const FieldHeader = struct {
            wfp: types.WireFormatPolicy,
            leaf_idx: LeafIndex,
            pos: u32,
        };

        fn readFieldHeader(
            data: []const u8,
            pos: u32,
        ) DecodeError!FieldHeader {
            const wfp_r = try codec.decodeUint8(data, pos);
            const li_r = try codec.decodeUint32(
                data,
                wfp_r.pos,
            );
            return .{
                .wfp = @enumFromInt(wfp_r.value),
                .leaf_idx = LeafIndex.fromU32(li_r.value),
                .pos = li_r.pos,
            };
        }

        fn readGroupContext(
            allocator: std.mem.Allocator,
            data: []const u8,
            pos: u32,
        ) (DecodeError || error{OutOfMemory})!struct {
            value: GC,
            pos: u32,
        } {
            const vr = try varint.decode(data, pos);
            const gc_len = vr.value;
            const p = vr.pos;
            if (p + gc_len > data.len) return error.Truncated;
            const gc_r = try GC.decode(
                allocator,
                data[p..][0..gc_len],
                0,
            );
            return .{
                .value = gc_r.value,
                .pos = p + gc_len,
            };
        }

        fn readSecrets(
            data: []const u8,
            pos: u32,
            result: *GS,
        ) DecodeError!u32 {
            var p = pos;
            inline for (std.meta.fields(
                schedule.EpochSecrets(P),
            )) |field| {
                if (field.type == [P.nh]u8) {
                    if (p + P.nh > data.len) {
                        return error.Truncated;
                    }
                    @memcpy(
                        &@field(
                            result.epoch_secrets,
                            field.name,
                        ),
                        data[p..][0..P.nh],
                    );
                    p += P.nh;
                }
            }
            p = try readHash(
                data,
                p,
                &result.interim_transcript_hash,
            );
            p = try readHash(
                data,
                p,
                &result.confirmed_transcript_hash,
            );
            // Reject all-zero critical secrets (would break
            // forward secrecy for subsequent epochs).
            try validateSecretNonZero(
                &result.epoch_secrets.init_secret,
            );
            try validateSecretNonZero(
                &result.epoch_secrets.encryption_secret,
            );
            try validateSecretNonZero(
                &result.epoch_secrets.sender_data_secret,
            );
            return p;
        }

        fn validateSecretNonZero(
            secret: *const [P.nh]u8,
        ) DecodeError!void {
            const zero: [P.nh]u8 = .{0} ** P.nh;
            if (std.mem.eql(u8, secret, &zero))
                return error.CorruptState;
        }

        fn readHash(
            data: []const u8,
            pos: u32,
            out: *[P.nh]u8,
        ) DecodeError!u32 {
            if (pos + P.nh > data.len) return error.Truncated;
            @memcpy(out, data[pos..][0..P.nh]);
            return pos + P.nh;
        }

        fn readTree(
            allocator: std.mem.Allocator,
            data: []const u8,
            pos: u32,
        ) (DecodeError || error{OutOfMemory})!struct {
            value: RatchetTree,
            pos: u32,
        } {
            const lc_r = try codec.decodeUint32(data, pos);
            const leaf_count = lc_r.value;
            var p = lc_r.pos;
            var tree = try RatchetTree.init(
                allocator,
                leaf_count,
            );
            errdefer tree.deinit();
            const width = tree_math.nodeWidth(leaf_count);
            var i: u32 = 0;
            while (i < width) : (i += 1) {
                const nr = try readNode(allocator, data, p);
                p = nr.pos;
                tree.nodes[i] = nr.value;
            }
            tree.owns_contents = true;
            return .{ .value = tree, .pos = p };
        }

        fn readNode(
            allocator: std.mem.Allocator,
            data: []const u8,
            pos: u32,
        ) (DecodeError || error{OutOfMemory})!struct {
            value: ?Node,
            pos: u32,
        } {
            const tag_r = try codec.decodeUint8(data, pos);
            if (tag_r.value == 0) {
                return .{ .value = null, .pos = tag_r.pos };
            }
            const vr = try varint.decode(data, tag_r.pos);
            const node_len = vr.value;
            var p = vr.pos;
            if (p + node_len > data.len) {
                return error.Truncated;
            }
            const node_data = data[p..][0..node_len];
            const nr = try Node.decode(
                allocator,
                node_data,
                0,
            );
            p += node_len;
            return .{ .value = nr.value, .pos = p };
        }

        // -- Utility ---------

        fn copyRaw(
            buf: []u8,
            pos: u32,
            src: []const u8,
        ) EncodeError!u32 {
            const len: u32 = @intCast(src.len);
            if (pos + len > buf.len) {
                return error.BufferTooSmall;
            }
            @memcpy(buf[pos..][0..len], src);
            return pos + len;
        }

        fn varintPrefixedCopy(
            buf: []u8,
            pos: u32,
            src: []const u8,
        ) EncodeError!u32 {
            const len: u32 = @intCast(src.len);
            const p = try varint.encode(buf, pos, len);
            if (p + len > buf.len) {
                return error.BufferTooSmall;
            }
            @memcpy(buf[p..][0..len], src);
            return p + len;
        }
    };
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import(
    "../credential/credential.zig",
).Credential;

const CipherSuite = types.CipherSuite;
const ProtocolVersion = types.ProtocolVersion;
const ExtensionType = types.ExtensionType;
const ProposalType = types.ProposalType;
const CredentialType = types.CredentialType;

fn makeCreatorLeaf() node_mod.LeafNode {
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]ExtensionType{};
    const prop_types = comptime [_]ProposalType{};
    const cred_types = comptime [_]CredentialType{.basic};

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

test "serialize/deserialize round-trip preserves fields" {
    const alloc = testing.allocator;
    const S = Serializer(Default);

    var gs = try state_mod.createGroup(
        Default,
        alloc,
        "test-group",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    const data = try S.serialize(alloc, &gs);
    defer {
        std.crypto.secureZero(u8, @volatileCast(data));
        alloc.free(data);
    }

    var gs2 = try S.deserialize(alloc, data);
    defer S.deinitDeserialized(&gs2);

    // group_id.
    try testing.expectEqualSlices(
        u8,
        gs.groupId(),
        gs2.groupId(),
    );
    // cipher_suite.
    try testing.expectEqual(
        gs.cipherSuite(),
        gs2.cipherSuite(),
    );
    // leaf_count.
    try testing.expectEqual(gs.leafCount(), gs2.leafCount());
    // my_leaf_index.
    try testing.expectEqual(
        gs.my_leaf_index.toU32(),
        gs2.my_leaf_index.toU32(),
    );
    // wire_format_policy.
    try testing.expectEqual(
        gs.wire_format_policy,
        gs2.wire_format_policy,
    );
    // transcript hashes.
    try testing.expectEqualSlices(
        u8,
        &gs.interim_transcript_hash,
        &gs2.interim_transcript_hash,
    );
    try testing.expectEqualSlices(
        u8,
        &gs.confirmed_transcript_hash,
        &gs2.confirmed_transcript_hash,
    );
}

test "deserialized state epoch matches original" {
    const alloc = testing.allocator;
    const S = Serializer(Default);

    var gs = try state_mod.createGroup(
        Default,
        alloc,
        "epoch-group",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    const data = try S.serialize(alloc, &gs);
    defer {
        std.crypto.secureZero(u8, @volatileCast(data));
        alloc.free(data);
    }

    var gs2 = try S.deserialize(alloc, data);
    defer S.deinitDeserialized(&gs2);

    try testing.expectEqual(gs.epoch(), gs2.epoch());
    // Epoch secrets must match.
    try testing.expectEqualSlices(
        u8,
        &gs.epoch_secrets.epoch_secret,
        &gs2.epoch_secrets.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &gs.epoch_secrets.init_secret,
        &gs2.epoch_secrets.init_secret,
    );
}

test "wrong magic is rejected" {
    const alloc = testing.allocator;
    const S = Serializer(Default);

    var gs = try state_mod.createGroup(
        Default,
        alloc,
        "magic-group",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    const data = try S.serialize(alloc, &gs);
    defer {
        std.crypto.secureZero(u8, @volatileCast(data));
        alloc.free(data);
    }

    // Corrupt the magic bytes.
    var bad = try alloc.dupe(u8, data);
    defer alloc.free(bad);
    bad[0] = 'X';

    const result = S.deserialize(alloc, bad);
    try testing.expectError(error.InvalidEnumValue, result);
}

test "wrong version is rejected" {
    const alloc = testing.allocator;
    const S = Serializer(Default);

    var gs = try state_mod.createGroup(
        Default,
        alloc,
        "ver-group",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    const data = try S.serialize(alloc, &gs);
    defer {
        std.crypto.secureZero(u8, @volatileCast(data));
        alloc.free(data);
    }

    // Corrupt the version byte (offset 4).
    var bad = try alloc.dupe(u8, data);
    defer alloc.free(bad);
    bad[4] = 0xFF;

    const result = S.deserialize(alloc, bad);
    try testing.expectError(error.InvalidEnumValue, result);
}

test "all-zero init_secret rejected as CorruptState" {
    const alloc = testing.allocator;
    const S = Serializer(Default);

    var gs = try state_mod.createGroup(
        Default,
        alloc,
        "zero-test",
        makeCreatorLeaf(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Zero the init_secret before serializing.
    @memset(&gs.epoch_secrets.init_secret, 0);

    const data = try S.serialize(alloc, &gs);
    defer {
        std.crypto.secureZero(u8, @volatileCast(data));
        alloc.free(data);
    }

    const result = S.deserialize(alloc, data);
    try testing.expectError(error.CorruptState, result);
}
