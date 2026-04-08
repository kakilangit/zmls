//! Wire protocol envelope framing.
//!
//! Encodes and decodes message envelopes for transport between
//! Client and Server. Works with byte slices (same as the zmls
//! core codec). Applications using their own framing (HTTP,
//! gRPC, WebSocket) skip the envelope entirely.
//!
//! Envelope format (big-endian):
//!
//!   version:          u8  = 1
//!   message_type:     u8  (MessageType)
//!   group_id_length:  u16
//!   group_id:         [group_id_length]u8
//!   payload_length:   u32
//!   payload:          [payload_length]u8

const std = @import("std");
const Allocator = std.mem.Allocator;
const MessageType =
    @import("../ports/transport.zig").MessageType;

/// Current envelope version.
pub const version: u8 = 1;

/// Maximum allowed group_id length.
pub const max_group_id_length: u32 = 256;

/// Default maximum payload size (4 MiB).
pub const default_max_payload: u32 = 4 * 1024 * 1024;

pub const EnvelopeError = error{
    EnvelopeTooLarge,
    InvalidEnvelope,
    Truncated,
};

/// Decoded envelope.
pub const Envelope = struct {
    message_type: MessageType,
    group_id: []u8,
    payload: []u8,

    pub fn deinit(self: *Envelope, allocator: Allocator) void {
        allocator.free(self.group_id);
        allocator.free(self.payload);
        self.* = undefined;
    }
};

/// Minimum header size: version(1) + type(1) + gid_len(2) +
/// payload_len(4) = 8 bytes (with zero-length group_id).
const header_fixed: u32 = 8;

/// Encode an envelope into a newly allocated buffer.
pub fn writeEnvelope(
    allocator: Allocator,
    message_type: MessageType,
    group_id: []const u8,
    payload: []const u8,
) (Allocator.Error || EnvelopeError)![]u8 {
    if (group_id.len > max_group_id_length)
        return error.InvalidEnvelope;

    const gid_len: u16 = @intCast(group_id.len);
    const pay_len: u32 = @intCast(payload.len);
    const total: usize = header_fixed + group_id.len +
        payload.len;

    const buf = try allocator.alloc(u8, total);
    errdefer allocator.free(buf);

    var pos: usize = 0;

    // version
    buf[pos] = version;
    pos += 1;

    // message_type
    buf[pos] = @intFromEnum(message_type);
    pos += 1;

    // group_id_length (big-endian u16)
    std.mem.writeInt(u16, buf[pos..][0..2], gid_len, .big);
    pos += 2;

    // group_id
    @memcpy(buf[pos..][0..group_id.len], group_id);
    pos += group_id.len;

    // payload_length (big-endian u32)
    std.mem.writeInt(u32, buf[pos..][0..4], pay_len, .big);
    pos += 4;

    // payload
    @memcpy(buf[pos..][0..payload.len], payload);

    return buf;
}

/// Decode an envelope from a byte buffer.
///
/// Returns an `Envelope` with allocator-owned `group_id` and
/// `payload` slices. Caller must call `envelope.deinit(alloc)`.
pub fn readEnvelope(
    allocator: Allocator,
    data: []const u8,
    maximum_payload: u32,
) (Allocator.Error || EnvelopeError)!Envelope {
    if (data.len < header_fixed) return error.Truncated;

    var pos: usize = 0;

    // version
    const ver = data[pos];
    pos += 1;
    if (ver != version) return error.InvalidEnvelope;

    // message_type
    const mt_raw = data[pos];
    pos += 1;
    const mt: MessageType = switch (mt_raw) {
        1 => .commit,
        2 => .welcome,
        3 => .proposal,
        4 => .application,
        5 => .group_info,
        else => return error.InvalidEnvelope,
    };

    // group_id_length
    const gid_len = std.mem.readInt(
        u16,
        data[pos..][0..2],
        .big,
    );
    pos += 2;
    if (gid_len > max_group_id_length)
        return error.InvalidEnvelope;

    // group_id
    if (data.len < pos + gid_len) return error.Truncated;
    const gid_src = data[pos..][0..gid_len];
    pos += gid_len;

    // payload_length
    if (data.len < pos + 4) return error.Truncated;
    const pay_len = std.mem.readInt(
        u32,
        data[pos..][0..4],
        .big,
    );
    pos += 4;
    if (pay_len > maximum_payload)
        return error.EnvelopeTooLarge;

    // payload
    if (data.len < pos + pay_len) return error.Truncated;
    const pay_src = data[pos..][0..pay_len];

    // Allocate copies.
    const gid = try allocator.alloc(u8, gid_len);
    errdefer allocator.free(gid);
    @memcpy(gid, gid_src);

    const pay = try allocator.alloc(u8, pay_len);
    errdefer allocator.free(pay);
    @memcpy(pay, pay_src);

    return .{
        .message_type = mt,
        .group_id = gid,
        .payload = pay,
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

test "Envelope: round-trip encode/decode" {
    const encoded = try writeEnvelope(
        testing.allocator,
        .commit,
        "my-group",
        "payload-data",
    );
    defer testing.allocator.free(encoded);

    var env = try readEnvelope(
        testing.allocator,
        encoded,
        default_max_payload,
    );
    defer env.deinit(testing.allocator);

    try testing.expectEqual(MessageType.commit, env.message_type);
    try testing.expectEqualSlices(u8, "my-group", env.group_id);
    try testing.expectEqualSlices(u8, "payload-data", env.payload);
}

test "Envelope: oversized payload rejected" {
    const encoded = try writeEnvelope(
        testing.allocator,
        .application,
        "g",
        "big-payload",
    );
    defer testing.allocator.free(encoded);

    // Set max to 5 bytes — "big-payload" is 11.
    const result = readEnvelope(testing.allocator, encoded, 5);
    try testing.expectError(error.EnvelopeTooLarge, result);
}

test "Envelope: truncated input rejected" {
    const result = readEnvelope(testing.allocator, "abc", 1024);
    try testing.expectError(error.Truncated, result);
}

test "Envelope: invalid version rejected" {
    var buf: [8]u8 = .{0} ** 8;
    buf[0] = 99; // bad version
    const result = readEnvelope(testing.allocator, &buf, 1024);
    try testing.expectError(error.InvalidEnvelope, result);
}

test "Envelope: invalid message type rejected" {
    var buf: [8]u8 = .{0} ** 8;
    buf[0] = version;
    buf[1] = 0xFF; // invalid MessageType
    const result = readEnvelope(testing.allocator, &buf, 1024);
    try testing.expectError(error.InvalidEnvelope, result);
}

test "Envelope: group_id too long rejected" {
    const gid = "g" ** 300; // > 256
    const result = writeEnvelope(
        testing.allocator,
        .commit,
        gid,
        "payload",
    );
    try testing.expectError(error.InvalidEnvelope, result);
}

test "Envelope: empty group_id and payload" {
    const encoded = try writeEnvelope(
        testing.allocator,
        .welcome,
        "",
        "",
    );
    defer testing.allocator.free(encoded);

    var env = try readEnvelope(
        testing.allocator,
        encoded,
        default_max_payload,
    );
    defer env.deinit(testing.allocator);

    try testing.expectEqual(MessageType.welcome, env.message_type);
    try testing.expectEqual(@as(usize, 0), env.group_id.len);
    try testing.expectEqual(@as(usize, 0), env.payload.len);
}

test "Envelope: all message types round-trip" {
    const types = [_]MessageType{
        .commit, .welcome, .proposal, .application, .group_info,
    };
    for (types) |mt| {
        const encoded = try writeEnvelope(
            testing.allocator,
            mt,
            "g",
            "p",
        );
        defer testing.allocator.free(encoded);

        var env = try readEnvelope(
            testing.allocator,
            encoded,
            default_max_payload,
        );
        defer env.deinit(testing.allocator);

        try testing.expectEqual(mt, env.message_type);
    }
}
