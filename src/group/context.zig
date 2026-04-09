//! GroupContext per RFC 9420 Section 8.1. Holds protocol version,
//! cipher suite, group ID, epoch, tree hash, transcript hash,
//! and extensions.
// GroupContext per RFC 9420 Section 8.1.
//
//   struct {
//       ProtocolVersion version;
//       CipherSuite cipher_suite;
//       opaque group_id<V>;
//       uint64 epoch;
//       opaque tree_hash<V>;
//       opaque confirmed_transcript_hash<V>;
//       Extension extensions<V>;
//   } GroupContext;
//
// The GroupContext is hashed into the key schedule and signed as
// part of LeafNodeTBS and GroupInfoTBS. It uniquely identifies
// the group state at a given epoch.
//
// This type is generic over `nh` (hash output length in bytes)
// so that `tree_hash` and `confirmed_transcript_hash` are
// inline fixed-size arrays, not aliasing slices. This makes
// the struct safe to copy/move by value with no fixup needed.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const Extension = node_mod.Extension;
const Epoch = types.Epoch;

/// Maximum encoded GroupContext size for stack buffers.
pub const max_gc_encode: u32 = 65536;

// -- GroupContext -------------------------------------------------------------

/// The GroupContext captures the full state of a group at an
/// epoch. Generic over `nh` (hash output length) so hashes
/// are stored as fixed-size arrays, not pointer slices.
pub fn GroupContext(comptime nh: u32) type {
    return struct {
        version: ProtocolVersion,
        cipher_suite: CipherSuite,
        group_id: []const u8,
        epoch: Epoch,
        tree_hash: [nh]u8,
        confirmed_transcript_hash: [nh]u8,
        extensions: []const Extension,

        const Self = @This();

        pub fn encode(
            self: *const Self,
            buf: []u8,
            pos: u32,
        ) EncodeError!u32 {
            assert(self.group_id.len > 0);
            var p = pos;

            // ProtocolVersion version (u16).
            p = try codec.encodeUint16(
                buf,
                p,
                @intFromEnum(self.version),
            );

            // CipherSuite cipher_suite (u16).
            p = try codec.encodeUint16(
                buf,
                p,
                @intFromEnum(self.cipher_suite),
            );

            // opaque group_id<V>.
            p = try codec.encodeVarVector(
                buf,
                p,
                self.group_id,
            );

            // uint64 epoch.
            p = try codec.encodeUint64(buf, p, self.epoch);

            // opaque tree_hash<V>.
            p = try codec.encodeVarVector(
                buf,
                p,
                &self.tree_hash,
            );

            // opaque confirmed_transcript_hash<V>.
            p = try codec.encodeVarVector(
                buf,
                p,
                &self.confirmed_transcript_hash,
            );

            // Extension extensions<V>.
            p = try encodeExtensionList(
                buf,
                p,
                self.extensions,
            );

            return p;
        }

        pub fn decode(
            allocator: std.mem.Allocator,
            data: []const u8,
            pos: u32,
        ) (DecodeError || error{OutOfMemory})!struct {
            value: Self,
            pos: u32,
        } {
            var p = pos;

            // ProtocolVersion (u16).
            const ver_r = try codec.decodeUint16(data, p);
            p = ver_r.pos;

            // CipherSuite (u16).
            const cs_r = try codec.decodeUint16(data, p);
            p = cs_r.pos;

            // group_id<V>.
            const gid_r = try codec.decodeVarVectorLimited(
                allocator,
                data,
                p,
                types.max_public_key_length,
            );
            p = gid_r.pos;

            // uint64 epoch.
            const ep_r = try codec.decodeUint64(data, p);
            p = ep_r.pos;

            // tree_hash<V>.
            const th_r = try codec.decodeVarVectorLimited(
                allocator,
                data,
                p,
                types.max_hash_length,
            );
            errdefer allocator.free(th_r.value);
            p = th_r.pos;

            // confirmed_transcript_hash<V>.
            const cth_r = try codec.decodeVarVectorLimited(
                allocator,
                data,
                p,
                types.max_hash_length,
            );
            errdefer allocator.free(cth_r.value);
            p = cth_r.pos;

            // Extension extensions<V>.
            const ext_r = try decodeExtensionList(
                allocator,
                data,
                p,
            );
            p = ext_r.pos;

            // Copy decoded variable-length slices into
            // fixed-size arrays and free the heap copies.
            if (th_r.value.len != nh or
                cth_r.value.len != nh)
            {
                allocator.free(th_r.value);
                allocator.free(cth_r.value);
                return error.Truncated;
            }

            var tree_hash: [nh]u8 = undefined;
            var confirmed_th: [nh]u8 = undefined;
            @memcpy(&tree_hash, th_r.value);
            @memcpy(&confirmed_th, cth_r.value);
            allocator.free(th_r.value);
            allocator.free(cth_r.value);

            return .{
                .value = .{
                    .version = @enumFromInt(ver_r.value),
                    .cipher_suite = @enumFromInt(cs_r.value),
                    .group_id = gid_r.value,
                    .epoch = ep_r.value,
                    .tree_hash = tree_hash,
                    .confirmed_transcript_hash = confirmed_th,
                    .extensions = ext_r.value,
                },
                .pos = p,
            };
        }

        /// Serialize GroupContext to a stack buffer. Returns the
        /// encoded byte slice (pointing into `buf`).
        pub fn serialize(
            self: *const Self,
            buf: *[max_gc_encode]u8,
        ) EncodeError![]const u8 {
            const end = try self.encode(buf, 0);
            return buf[0..end];
        }

        /// Create a new GroupContext for the next epoch with
        /// updated tree_hash, confirmed_transcript_hash, and
        /// extensions. Clones group_id and extensions so the
        /// returned context is independently owned.
        pub fn updateForNewEpoch(
            self: *const Self,
            allocator: std.mem.Allocator,
            new_tree_hash: [nh]u8,
            new_confirmed_th: [nh]u8,
            new_extensions: []const Extension,
        ) (error{OutOfMemory} || errors.GroupError)!Self {
            const gid = try allocator.dupe(u8, self.group_id);
            errdefer allocator.free(gid);
            const exts = try node_mod.cloneExtensions(
                allocator,
                new_extensions,
            );
            return .{
                .version = self.version,
                .cipher_suite = self.cipher_suite,
                .group_id = gid,
                .epoch = std.math.add(u64, self.epoch, 1) catch
                    return error.EpochOverflow,
                .tree_hash = new_tree_hash,
                .confirmed_transcript_hash = new_confirmed_th,
                .extensions = exts,
            };
        }

        pub fn deinit(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            allocator.free(self.group_id);
            for (self.extensions) |*ext| {
                @constCast(ext).deinit(allocator);
            }
            allocator.free(self.extensions);
            self.* = undefined;
        }
    };
}

// -- Extension list codec helpers (shared with group_info.zig) ---------------

fn encodeExtensionList(
    buf: []u8,
    pos: u32,
    items: []const Extension,
) EncodeError!u32 {
    const gap: u32 = 4;
    const start = pos + gap;
    var p = start;

    for (items) |*ext| {
        p = try ext.encode(buf, p);
    }

    const inner_len: u32 = p - start;
    var len_buf: [4]u8 = undefined;
    const len_end = try varint.encode(
        &len_buf,
        0,
        inner_len,
    );

    const dest_start = pos + len_end;
    if (dest_start != start) {
        std.mem.copyForwards(
            u8,
            buf[dest_start..][0..inner_len],
            buf[start..][0..inner_len],
        );
    }
    @memcpy(buf[pos..][0..len_end], len_buf[0..len_end]);

    return dest_start + inner_len;
}

/// Free extension data slices allocated during decode.
fn freeDecodedExts(
    allocator: std.mem.Allocator,
    exts: []Extension,
) void {
    for (exts) |ext| allocator.free(ext.data);
}

fn decodeExtensionList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const Extension,
    pos: u32,
} {
    const max_extensions: u32 = 256;

    const vr = try varint.decode(data, pos);
    const total_len = vr.value;
    var p = vr.pos;

    if (total_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (p + total_len > data.len) return error.Truncated;

    const end = p + total_len;
    var temp: [256]Extension = undefined;
    var count: u32 = 0;

    while (p < end) {
        if (count >= max_extensions) {
            return error.VectorTooLarge;
        }
        const r = try Extension.decode(
            allocator,
            data,
            p,
        );
        temp[count] = r.value;
        count += 1;
        p = r.pos;
    }

    if (p != end) return error.Truncated;

    // RFC 9420 S13.4: reject duplicate extension types.
    var di: u32 = 0;
    while (di < count) : (di += 1) {
        var dj: u32 = di + 1;
        while (dj < count) : (dj += 1) {
            if (temp[di].extension_type ==
                temp[dj].extension_type)
            {
                freeDecodedExts(allocator, temp[0..count]);
                return error.DuplicateExtensionType;
            }
        }
    }

    const items = allocator.alloc(
        Extension,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(items, temp[0..count]);

    return .{ .value = items, .pos = p };
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const ExtensionType = types.ExtensionType;

/// Test helper: a non-generic GroupContext alias for nh=32.
const GC32 = GroupContext(32);

test "GroupContext encode/decode round-trip" {
    const alloc = testing.allocator;

    const gc = GC32{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .group_id = "my-group-id",
        .epoch = 5,
        .tree_hash = [_]u8{0xAA} ** 32,
        .confirmed_transcript_hash = [_]u8{0xBB} ** 32,
        .extensions = &.{},
    };

    var buf: [512]u8 = undefined;
    const end = try gc.encode(&buf, 0);

    var dec_r = try GC32.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProtocolVersion.mls10,
        dec_r.value.version,
    );
    try testing.expectEqual(
        CipherSuite.mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        dec_r.value.cipher_suite,
    );
    try testing.expectEqualSlices(
        u8,
        "my-group-id",
        dec_r.value.group_id,
    );
    try testing.expectEqual(@as(u64, 5), dec_r.value.epoch);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0xAA} ** 32,
        &dec_r.value.tree_hash,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0xBB} ** 32,
        &dec_r.value.confirmed_transcript_hash,
    );
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.extensions.len,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "GroupContext with extensions round-trip" {
    const alloc = testing.allocator;

    const ext = Extension{
        .extension_type = @enumFromInt(0xFE01),
        .data = "ext-payload",
    };
    const exts = [_]Extension{ext};

    const gc = GC32{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .group_id = "g",
        .epoch = 0,
        .tree_hash = [_]u8{0} ** 32,
        .confirmed_transcript_hash = [_]u8{0} ** 32,
        .extensions = &exts,
    };

    var buf: [512]u8 = undefined;
    const end = try gc.encode(&buf, 0);

    var dec_r = try GC32.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.extensions.len,
    );
    try testing.expectEqualSlices(
        u8,
        "ext-payload",
        dec_r.value.extensions[0].data,
    );
}

test "GroupContext serialize into stack buffer" {
    const gc = GC32{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .group_id = "group",
        .epoch = 1,
        .tree_hash = [_]u8{0} ** 32,
        .confirmed_transcript_hash = [_]u8{0} ** 32,
        .extensions = &.{},
    };

    var buf: [max_gc_encode]u8 = undefined;
    const bytes = try gc.serialize(&buf);

    // Should encode at least version(2) + suite(2) + varint +
    // group_id + epoch(8) + ...
    try testing.expect(bytes.len > 20);

    // Should start with version (0x0001 = mls10).
    try testing.expectEqual(@as(u8, 0x00), bytes[0]);
    try testing.expectEqual(@as(u8, 0x01), bytes[1]);
}

test "updateForNewEpoch increments epoch and owns data" {
    const allocator = testing.allocator;
    const gc = GC32{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .group_id = "group",
        .epoch = 3,
        .tree_hash = [_]u8{0} ** 32,
        .confirmed_transcript_hash = [_]u8{0} ** 32,
        .extensions = &.{},
    };

    const new_th = [_]u8{0xAA} ** 32;
    const new_cth = [_]u8{0xBB} ** 32;
    var new_gc = try gc.updateForNewEpoch(
        allocator,
        new_th,
        new_cth,
        &.{},
    );
    defer new_gc.deinit(allocator);

    try testing.expectEqual(@as(u64, 4), new_gc.epoch);
    try testing.expectEqualSlices(u8, &new_th, &new_gc.tree_hash);
    try testing.expectEqualSlices(u8, &new_cth, &new_gc.confirmed_transcript_hash);
    try testing.expectEqualSlices(u8, "group", new_gc.group_id);
    try testing.expectEqual(
        CipherSuite.mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        new_gc.cipher_suite,
    );
}

test "updateForNewEpoch: old and new contexts are independent" {
    const allocator = testing.allocator;

    // Build a heap-owned initial context (mimics decode).
    const gid = try allocator.dupe(u8, "owned-group");
    var old_gc = GC32{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .group_id = gid,
        .epoch = 5,
        .tree_hash = [_]u8{1} ** 32,
        .confirmed_transcript_hash = [_]u8{2} ** 32,
        .extensions = &.{},
    };

    var new_gc = try old_gc.updateForNewEpoch(
        allocator,
        [_]u8{3} ** 32,
        [_]u8{4} ** 32,
        &.{},
    );

    // Free old — new must still be usable.
    old_gc.deinit(allocator);
    try testing.expectEqualSlices(
        u8,
        "owned-group",
        new_gc.group_id,
    );
    try testing.expectEqual(@as(u64, 6), new_gc.epoch);

    // Free new.
    new_gc.deinit(allocator);
}
