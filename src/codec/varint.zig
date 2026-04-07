//! Variable-length integer encoding/decoding per RFC 9000 Section 16.
//! Supports 1/2/4-byte encodings with minimum-encoding enforcement.
// Variable-length integer encoding per RFC 9420 Section 2.1.2.
//
// Based on RFC 9000 Section 16, with the additional requirement that the
// encoding must use the minimum number of bytes. The two most significant
// bits of the first byte encode the length:
//
//   Prefix  Bytes  Usable bits  Range
//   00      1      6            0..63
//   01      2      14           64..16_383
//   10      4      30           16_384..1_073_741_823
//   11      (invalid)

const std = @import("std");
const assert = std.debug.assert;
const errors = @import("../common/errors.zig");

const DecodeError = errors.DecodeError;

/// Maximum value representable: 2^30 - 1.
pub const max_value: u32 = (1 << 30) - 1;

/// Encode a variable-length integer into `buf` starting at `pos`.
/// Returns the new position after writing.
/// The value must fit in 30 bits (max 1_073_741_823).
pub fn encode(buf: []u8, pos: u32, value: u32) error{BufferTooSmall}!u32 {
    if (value < 0x40) {
        // 1-byte form: prefix 00, 6 usable bits.
        if (pos >= buf.len) return error.BufferTooSmall;
        buf[pos] = @intCast(value);
        return pos + 1;
    } else if (value < 0x4000) {
        // 2-byte form: prefix 01, 14 usable bits.
        if (pos + 2 > buf.len) return error.BufferTooSmall;
        const raw: u16 = 0x4000 | @as(u16, @intCast(value));
        const bytes = std.mem.toBytes(
            std.mem.nativeTo(u16, raw, .big),
        );
        buf[pos] = bytes[0];
        buf[pos + 1] = bytes[1];
        return pos + 2;
    } else if (value <= max_value) {
        // 4-byte form: prefix 10, 30 usable bits.
        if (pos + 4 > buf.len) return error.BufferTooSmall;
        const raw: u32 = 0x80000000 | value;
        const bytes = std.mem.toBytes(
            std.mem.nativeTo(u32, raw, .big),
        );
        buf[pos] = bytes[0];
        buf[pos + 1] = bytes[1];
        buf[pos + 2] = bytes[2];
        buf[pos + 3] = bytes[3];
        return pos + 4;
    } else {
        // Values above 2^30 - 1 cannot be encoded.
        return error.BufferTooSmall;
    }
}

/// Returns the number of bytes needed to encode the given value.
pub fn encodedLength(value: u32) u32 {
    if (value < 0x40) return 1;
    if (value < 0x4000) return 2;
    return 4;
}

/// Decode a variable-length integer from `data` starting at `pos`.
/// Returns the decoded value and the new position.
pub fn decode(
    data: []const u8,
    pos: u32,
) DecodeError!struct { value: u32, pos: u32 } {
    if (pos >= data.len) return error.Truncated;
    const first_byte = data[pos];
    const prefix: u2 = @intCast(first_byte >> 6);

    switch (prefix) {
        0b00 => {
            // 1-byte form: value is the lower 6 bits.
            return .{
                .value = @as(u32, first_byte & 0x3f),
                .pos = pos + 1,
            };
        },
        0b01 => {
            // 2-byte form: 14 usable bits.
            if (pos + 2 > data.len) return error.Truncated;
            const value: u32 = (@as(u32, first_byte & 0x3f) << 8) |
                @as(u32, data[pos + 1]);
            // Minimum encoding check: must be >= 64.
            if (value < 0x40) return error.NonMinimalVarint;
            return .{ .value = value, .pos = pos + 2 };
        },
        0b10 => {
            // 4-byte form: 30 usable bits.
            if (pos + 4 > data.len) return error.Truncated;
            const value: u32 = (@as(u32, first_byte & 0x3f) << 24) |
                (@as(u32, data[pos + 1]) << 16) |
                (@as(u32, data[pos + 2]) << 8) |
                @as(u32, data[pos + 3]);
            // Minimum encoding check: must be >= 16_384.
            if (value < 0x4000) return error.NonMinimalVarint;
            return .{ .value = value, .pos = pos + 4 };
        },
        0b11 => {
            return error.InvalidVarintPrefix;
        },
    }
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;

fn roundTrip(value: u32) !void {
    var buf: [4]u8 = undefined;
    const write_pos = try encode(&buf, 0, value);
    const result = try decode(&buf, 0);
    try testing.expectEqual(value, result.value);
    try testing.expectEqual(write_pos, result.pos);
}

test "varint round-trip boundary values" {
    // 1-byte range.
    try roundTrip(0);
    try roundTrip(63);
    // 2-byte range.
    try roundTrip(64);
    try roundTrip(16383);
    // 4-byte range.
    try roundTrip(16384);
    try roundTrip(max_value);
}

test "varint encoded length" {
    try testing.expectEqual(@as(u32, 1), encodedLength(0));
    try testing.expectEqual(@as(u32, 1), encodedLength(63));
    try testing.expectEqual(@as(u32, 2), encodedLength(64));
    try testing.expectEqual(@as(u32, 2), encodedLength(16383));
    try testing.expectEqual(@as(u32, 4), encodedLength(16384));
    try testing.expectEqual(@as(u32, 4), encodedLength(max_value));
}

test "varint RFC examples" {
    // Per RFC 9420 Section 2.1.2:
    // 0x9d7f3e7d decodes to 494_878_333.
    {
        const bytes = [_]u8{ 0x9d, 0x7f, 0x3e, 0x7d };
        const result = try decode(&bytes, 0);
        try testing.expectEqual(@as(u32, 494_878_333), result.value);
    }
    // 0x7bbd decodes to 15_293.
    {
        const bytes = [_]u8{ 0x7b, 0xbd };
        const result = try decode(&bytes, 0);
        try testing.expectEqual(@as(u32, 15_293), result.value);
    }
    // 0x25 decodes to 37.
    {
        const bytes = [_]u8{0x25};
        const result = try decode(&bytes, 0);
        try testing.expectEqual(@as(u32, 37), result.value);
    }
}

test "varint reject invalid prefix 0b11" {
    const bytes = [_]u8{0xC0};
    const result = decode(&bytes, 0);
    try testing.expectError(error.InvalidVarintPrefix, result);
}

test "varint reject non-minimal 2-byte encoding" {
    // Value 10 encoded in 2 bytes (should be 1 byte).
    const bytes = [_]u8{ 0x40, 0x0a };
    const result = decode(&bytes, 0);
    try testing.expectError(error.NonMinimalVarint, result);
}

test "varint reject non-minimal 4-byte encoding" {
    // Value 100 encoded in 4 bytes (should be 2 bytes).
    const bytes = [_]u8{ 0x80, 0x00, 0x00, 0x64 };
    const result = decode(&bytes, 0);
    try testing.expectError(error.NonMinimalVarint, result);
}

test "varint reject truncated input" {
    // 2-byte prefix but only 1 byte available.
    const bytes = [_]u8{0x40};
    const result = decode(&bytes, 0);
    try testing.expectError(error.Truncated, result);
}

test "varint encode buffer too small" {
    var buf: [1]u8 = undefined;
    // Value 64 needs 2 bytes but buffer is only 1.
    const result = encode(&buf, 0, 64);
    try testing.expectError(error.BufferTooSmall, result);
}

test "varint encode rejects value above 2^30-1" {
    var buf: [8]u8 = undefined;
    // 2^30 is the first value that can't be encoded.
    const result = encode(&buf, 0, 1 << 30);
    try testing.expectError(error.BufferTooSmall, result);
}
