//! TLS presentation language encoder/decoder for MLS wire formats.
//! Handles big-endian integers, fixed/variable-length vectors, and
//! optional values per RFC 9420 Section 2.1.
// TLS presentation language encoder/decoder for MLS wire formats.
//
// Per RFC 9420 Section 2.1: MLS uses the TLS presentation language with two
// extensions — optional values and variable-size vector length headers.
//
// This module provides generic encode/decode over byte slices with explicit
// position tracking. Covers: fixed-width integers (big-endian), fixed-length
// vectors, variable-length vectors (varint-prefixed), and optional<T>.

const std = @import("std");
const assert = std.debug.assert;
const varint = @import("varint.zig");
const errors = @import("../common/errors.zig");

const DecodeError = errors.DecodeError;
const max_vec_length = @import("../common/types.zig").max_vec_length;

pub const EncodeError = error{ BufferTooSmall, MissingConfirmationTag };

// -- Encoding ----------------------------------------------------------------

/// Write a single byte into `buf` at `pos`. Returns new position.
pub fn encodeUint8(
    buf: []u8,
    pos: u32,
    value: u8,
) EncodeError!u32 {
    if (pos >= buf.len) return error.BufferTooSmall;
    buf[pos] = value;
    return pos + 1;
}

/// Write a big-endian u16 into `buf` at `pos`. Returns new position.
pub fn encodeUint16(
    buf: []u8,
    pos: u32,
    value: u16,
) EncodeError!u32 {
    if (pos + 2 > buf.len) return error.BufferTooSmall;
    const bytes = std.mem.toBytes(
        std.mem.nativeTo(u16, value, .big),
    );
    buf[pos] = bytes[0];
    buf[pos + 1] = bytes[1];
    return pos + 2;
}

/// Write a big-endian u32 into `buf` at `pos`. Returns new position.
pub fn encodeUint32(
    buf: []u8,
    pos: u32,
    value: u32,
) EncodeError!u32 {
    if (pos + 4 > buf.len) return error.BufferTooSmall;
    const bytes = std.mem.toBytes(
        std.mem.nativeTo(u32, value, .big),
    );
    @memcpy(buf[pos..][0..4], &bytes);
    return pos + 4;
}

/// Write a big-endian u64 into `buf` at `pos`. Returns new position.
pub fn encodeUint64(
    buf: []u8,
    pos: u32,
    value: u64,
) EncodeError!u32 {
    if (pos + 8 > buf.len) return error.BufferTooSmall;
    const bytes = std.mem.toBytes(
        std.mem.nativeTo(u64, value, .big),
    );
    @memcpy(buf[pos..][0..8], &bytes);
    return pos + 8;
}

/// Write a variable-length opaque vector: varint length prefix + raw bytes.
/// Per RFC 9420 Section 2.1.2.
pub fn encodeVarVector(
    buf: []u8,
    pos: u32,
    data: []const u8,
) EncodeError!u32 {
    assert(data.len <= max_vec_length);
    const len: u32 = @intCast(data.len);
    var p = try varint.encode(buf, pos, len);
    if (p + len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[p..][0..len], data);
    p += len;
    return p;
}

/// Write an optional<T>. If value is null, write 0x00 presence byte.
/// Otherwise write 0x01 followed by the encoded value.
/// The caller provides an encode function for the inner type.
pub fn encodeOptional(
    buf: []u8,
    pos: u32,
    value: anytype,
    encode_fn: fn ([]u8, u32, @TypeOf(value.?)) EncodeError!u32,
) EncodeError!u32 {
    if (value) |v| {
        const p = try encodeUint8(buf, pos, 1);
        return encode_fn(buf, p, v);
    } else {
        return encodeUint8(buf, pos, 0);
    }
}

// -- Decoding ----------------------------------------------------------------

/// Read a single byte from `data` at `pos`. Returns value and new position.
pub fn decodeUint8(
    data: []const u8,
    pos: u32,
) DecodeError!struct { value: u8, pos: u32 } {
    if (pos >= data.len) return error.Truncated;
    return .{ .value = data[pos], .pos = pos + 1 };
}

/// Read a big-endian u16 from `data` at `pos`.
pub fn decodeUint16(
    data: []const u8,
    pos: u32,
) DecodeError!struct { value: u16, pos: u32 } {
    if (pos + 2 > data.len) return error.Truncated;
    const value = std.mem.readInt(
        u16,
        data[pos..][0..2],
        .big,
    );
    return .{ .value = value, .pos = pos + 2 };
}

/// Read a big-endian u32 from `data` at `pos`.
pub fn decodeUint32(
    data: []const u8,
    pos: u32,
) DecodeError!struct { value: u32, pos: u32 } {
    if (pos + 4 > data.len) return error.Truncated;
    const value = std.mem.readInt(
        u32,
        data[pos..][0..4],
        .big,
    );
    return .{ .value = value, .pos = pos + 4 };
}

/// Read a big-endian u64 from `data` at `pos`.
pub fn decodeUint64(
    data: []const u8,
    pos: u32,
) DecodeError!struct { value: u64, pos: u32 } {
    if (pos + 8 > data.len) return error.Truncated;
    const value = std.mem.readInt(
        u64,
        data[pos..][0..8],
        .big,
    );
    return .{ .value = value, .pos = pos + 8 };
}

/// Read a variable-length opaque vector into a caller-provided buffer.
/// Returns the filled slice and new position.
pub fn decodeVarVectorBuf(
    data: []const u8,
    pos: u32,
    buf: []u8,
) DecodeError!struct { value: []u8, pos: u32 } {
    const vr = try varint.decode(data, pos);
    const len = vr.value;
    var p = vr.pos;
    if (len > max_vec_length) return error.VectorTooLarge;
    if (len > buf.len) return error.VectorTooLarge;
    if (p + len > data.len) return error.Truncated;
    @memcpy(buf[0..len], data[p..][0..len]);
    p += len;
    return .{ .value = buf[0..len], .pos = p };
}

/// Read a variable-length opaque vector, allocating the result.
pub fn decodeVarVector(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []u8,
    pos: u32,
} {
    const vr = try varint.decode(data, pos);
    const len = vr.value;
    var p = vr.pos;
    if (len > max_vec_length) return error.VectorTooLarge;
    if (p + len > data.len) return error.Truncated;
    const buf = allocator.alloc(u8, len) catch return error.OutOfMemory;
    errdefer allocator.free(buf);
    @memcpy(buf, data[p..][0..len]);
    p += len;
    return .{ .value = buf, .pos = p };
}

/// Skip over a variable-length vector without reading its contents.
/// Returns the position after the vector (varint header + payload).
pub fn skipVarVector(
    data: []const u8,
    pos: u32,
) DecodeError!u32 {
    const vr = try varint.decode(data, pos);
    const len = vr.value;
    const p = vr.pos;
    if (len > max_vec_length) return error.VectorTooLarge;
    if (p + len > data.len) return error.Truncated;
    return p + len;
}

/// Read a variable-length opaque vector as a zero-copy slice into
/// the source buffer. No allocation needed.
pub fn decodeVarVectorSlice(
    data: []const u8,
    pos: u32,
) DecodeError!struct { value: []const u8, pos: u32 } {
    const vr = try varint.decode(data, pos);
    const len = vr.value;
    const p = vr.pos;
    if (len > max_vec_length) return error.VectorTooLarge;
    if (p + len > data.len) return error.Truncated;
    return .{
        .value = data[p..][0..len],
        .pos = p + len,
    };
}

/// Like decodeVarVector but with a caller-specified max length.
pub fn decodeVarVectorLimited(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
    max_len: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []u8,
    pos: u32,
} {
    const vr = try varint.decode(data, pos);
    const len = vr.value;
    var p = vr.pos;
    if (len > max_len) return error.VectorTooLarge;
    if (p + len > data.len) return error.Truncated;
    const buf = allocator.alloc(u8, len) catch
        return error.OutOfMemory;
    errdefer allocator.free(buf);
    @memcpy(buf, data[p..][0..len]);
    p += len;
    return .{ .value = buf, .pos = p };
}

/// Like decodeVarVectorSlice but with a caller-specified max length.
pub fn decodeVarVectorSliceLimited(
    data: []const u8,
    pos: u32,
    max_len: u32,
) DecodeError!struct { value: []const u8, pos: u32 } {
    const vr = try varint.decode(data, pos);
    const len = vr.value;
    const p = vr.pos;
    if (len > max_len) return error.VectorTooLarge;
    if (p + len > data.len) return error.Truncated;
    return .{
        .value = data[p..][0..len],
        .pos = p + len,
    };
}

/// Read an optional<T>. Returns null if the presence byte is 0.
/// The caller provides a decode function for the inner type.
/// The decode function must accept ([]const u8, u32) and return
/// a struct with `.value` and `.pos` fields, or a DecodeError.
pub fn decodeOptional(
    data: []const u8,
    pos: u32,
    comptime T: type,
    comptime decode_fn: anytype,
) DecodeError!struct { value: ?T, pos: u32 } {
    const pr = try decodeUint8(data, pos);
    switch (pr.value) {
        0 => return .{ .value = null, .pos = pr.pos },
        1 => {
            const inner = try decode_fn(data, pr.pos);
            return .{ .value = inner.value, .pos = inner.pos };
        },
        else => return error.InvalidOptionalPrefix,
    }
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;

test "encode/decode uint8" {
    var buf: [1]u8 = undefined;
    const p = try encodeUint8(&buf, 0, 0xAB);
    try testing.expectEqual(@as(u32, 1), p);

    const r = try decodeUint8(&buf, 0);
    try testing.expectEqual(@as(u8, 0xAB), r.value);
}

test "encode/decode uint16 big-endian" {
    var buf: [2]u8 = undefined;
    const p = try encodeUint16(&buf, 0, 0x0102);
    try testing.expectEqual(@as(u32, 2), p);

    try testing.expectEqual(@as(u8, 0x01), buf[0]);
    try testing.expectEqual(@as(u8, 0x02), buf[1]);

    const r = try decodeUint16(&buf, 0);
    try testing.expectEqual(@as(u16, 0x0102), r.value);
}

test "encode/decode uint32 big-endian" {
    var buf: [4]u8 = undefined;
    const p = try encodeUint32(&buf, 0, 0x01020304);
    try testing.expectEqual(@as(u32, 4), p);

    const r = try decodeUint32(&buf, 0);
    try testing.expectEqual(@as(u32, 0x01020304), r.value);
}

test "encode/decode uint64 big-endian" {
    var buf: [8]u8 = undefined;
    const p = try encodeUint64(&buf, 0, 0x0102030405060708);
    try testing.expectEqual(@as(u32, 8), p);

    const r = try decodeUint64(&buf, 0);
    try testing.expectEqual(@as(u64, 0x0102030405060708), r.value);
}

test "encode/decode variable-length vector" {
    var buf: [128]u8 = undefined;
    const payload = "hello MLS";

    // Encode.
    const written = try encodeVarVector(&buf, 0, payload);

    // Decode.
    var decode_buf: [128]u8 = undefined;
    const r = try decodeVarVectorBuf(&buf, 0, &decode_buf);
    try testing.expectEqualSlices(u8, payload, r.value);
    try testing.expectEqual(written, r.pos);
}

test "decode variable-length vector rejects oversized" {
    // Encode a vector claiming to be max_vec_length + 1 bytes.
    var buf: [8]u8 = undefined;
    const p = try varint.encode(&buf, 0, max_vec_length + 1);
    _ = p;

    var decode_buf: [16]u8 = undefined;
    const result = decodeVarVectorBuf(&buf, 0, &decode_buf);
    try testing.expectError(error.VectorTooLarge, result);
}

test "decode uint16 truncated" {
    const buf = [_]u8{0x01};
    const result = decodeUint16(&buf, 0);
    try testing.expectError(error.Truncated, result);
}

test "decode optional present" {
    var buf: [16]u8 = undefined;
    // Write present (1) + a u16 value.
    var p = try encodeUint8(&buf, 0, 1);
    p = try encodeUint16(&buf, p, 42);

    const r = try decodeOptional(&buf, 0, u16, decodeUint16);
    try testing.expectEqual(@as(u16, 42), r.value.?);
    try testing.expectEqual(p, r.pos);
}

test "decode optional absent" {
    const buf = [_]u8{0x00};
    const r = try decodeOptional(&buf, 0, u16, decodeUint16);
    try testing.expectEqual(@as(?u16, null), r.value);
}

test "decode optional invalid prefix" {
    const buf = [_]u8{0x02};
    const result = decodeOptional(&buf, 0, u16, decodeUint16);
    try testing.expectError(error.InvalidOptionalPrefix, result);
}

test "encode uint8 buffer too small" {
    var buf: [0]u8 = undefined;
    const result = encodeUint8(&buf, 0, 0xFF);
    try testing.expectError(error.BufferTooSmall, result);
}

test "decodeVarVectorLimited rejects oversized vector" {
    var buf: [8]u8 = undefined;
    // Encode a varint length of 300 bytes.
    _ = try varint.encode(&buf, 0, 300);
    // Fill remaining with zeros (won't be enough, but limit
    // check fires first).
    const alloc = testing.allocator;
    const result = decodeVarVectorLimited(
        alloc,
        &buf,
        0,
        256,
    );
    try testing.expectError(error.VectorTooLarge, result);
    // Same length at exactly the limit: should fail with
    // Truncated (buffer too short) not VectorTooLarge.
    const result2 = decodeVarVectorLimited(
        alloc,
        &buf,
        0,
        300,
    );
    try testing.expectError(error.Truncated, result2);
}

test "global max_vec_length is 1 MiB" {
    try testing.expectEqual(
        @as(u32, 1 << 20),
        max_vec_length,
    );
}
